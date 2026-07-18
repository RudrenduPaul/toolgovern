"""``GovernedCodeExecutor`` -- gates every ``CodeBlock`` an AutoGen agent tries to run through
``toolgovern``'s classifier before a real ``CodeExecutor`` (``LocalCommandLineCodeExecutor``,
``DockerCommandLineCodeExecutor``, ``JupyterCodeExecutor``, ...) ever executes it.

Why this exists: ``LocalCommandLineCodeExecutor.execute_code_blocks()`` (confirmed by reading
``autogen_ext/code_executors/local/__init__.py`` in the real installed package -- see this
repo's PR description / session notes for the exact version) writes an LLM-generated ``code``
string straight to a file in ``work_dir`` and runs it as a local subprocess. The only existing
safeguard is a ``UserWarning`` raised once, at construction time -- not a runtime control, and
silently dropped by any code that filters Python warnings. That is
`microsoft/autogen#7462 <https://github.com/microsoft/autogen/issues/7462>`_, the flagship issue
this adapter addresses.

``GovernedCodeExecutor`` wraps any real ``CodeExecutor`` and inserts one governed checkpoint:
each ``CodeBlock.code`` string is run through ``govern_tool()`` -- the same core used by every
other language's toolgovern integration -- before the real executor is invoked for that block.
Concretely:

- TG01 (shell/process risk) evaluates the code string directly: ``rm -rf /``, a curl-pipe-to-
  shell, a fork bomb, a reverse shell, a base64-decode-then-exec payload, etc. are denied
  regardless of whether the code block claims to be ``python``, ``bash``, ``sh``, ``pwsh``, or
  any other ``LocalCommandLineCodeExecutor.SUPPORTED_LANGUAGES`` value -- toolgovern's
  ``extract_command()`` treats a ``code``-named argument as command-like text directly (see
  ``python/src/toolgovern/classifier/util.py``'s ``_COMMAND_KEYS``), so a Python code block
  containing ``os.system("rm -rf /")`` is caught by the exact same ``TG01-rm-rf`` rule a raw
  shell tool call would be.
- TG02 (filesystem scope) scans the code string for path-like literals via
  ``extract_path_from_code()`` (the "extractPathFromCode-equivalent logic" named in this
  adapter's build task -- already shipped in the Foundation core, not new work here) and denies
  a ``"../"``-traversal write such as ``open('../../pwned.txt', 'w')`` -- the exact pattern
  `microsoft/autogen#7181 <https://github.com/microsoft/autogen/pull/7181>`_ patches natively
  inside ``LocalCommandLineCodeExecutor`` itself, via ``TG02-path-traversal``.

A denied block raises ``toolgovern.ToolGovernDenialError`` -- the real executor's
``execute_code_blocks()`` is never called for that block, or for any block after it in the same
batch (gating stops at the first denial, mirroring the real executor's own behavior of stopping
at the first block with a nonzero exit code).

**What this does not do.** This is a pre-execution argument/string classifier, not a sandbox. It
cannot enforce process-level resource limits (CPU/memory/wall-clock caps), filesystem/network
namespace isolation, or defend against a malicious payload sophisticated enough to evade every
TG01/TG02 pattern (see ``docs/security-model.md`` in the toolgovern core for the full, honest
disclosure of that classifier's known evasion classes). For genuine process isolation, wrap
``DockerCommandLineCodeExecutor`` (or a Firecracker/gVisor/WASM executor) with
``GovernedCodeExecutor`` instead of ``LocalCommandLineCodeExecutor`` -- the two concerns are
complementary, not substitutes for each other, exactly as
`microsoft/autogen#7230 <https://github.com/microsoft/autogen/issues/7230>`_ asks for.
"""

from __future__ import annotations

import dataclasses
from typing import Any, List, Mapping, Optional

from autogen_core import CancellationToken
from autogen_core.code_executor import CodeBlock, CodeExecutor, CodeResult
from toolgovern import GovernToolOptions, ToolDefinition, govern_tool

from ._sync_bridge import run_coroutine_sync

DEFAULT_TOOL_NAME = "autogen.code_executor"

__all__ = ["GovernedCodeExecutor", "DEFAULT_TOOL_NAME"]


class GovernedCodeExecutor(CodeExecutor):
    """Wraps a real ``CodeExecutor`` so every ``CodeBlock`` passed to ``execute_code_blocks()``
    is classified by toolgovern before that block reaches the wrapped executor's real
    ``execute_code_blocks()``.

    ``executor`` can be any concrete ``CodeExecutor`` -- ``LocalCommandLineCodeExecutor``,
    ``DockerCommandLineCodeExecutor``, ``JupyterCodeExecutor``, an Azure/ACA dynamic-sessions
    executor -- since this class only ever calls the public ``CodeExecutor`` interface
    (``execute_code_blocks``/``start``/``stop``/``restart``) on it; it does not subclass or
    monkey-patch the wrapped executor.

    ``options`` is passed straight through to ``govern_tool()`` -- the same
    ``GovernToolOptions`` (scope, policy, scope_registry, trace, approval handling) any other
    governed tool in a process would use. Every ``CodeBlock``'s ``code`` and ``language`` are
    passed to the classifier as ``{"code": ..., "language": ...}``, which is what
    ``extract_command()``/``extract_path()`` (see module docstring) already know how to read.
    """

    def __init__(
        self,
        executor: CodeExecutor,
        options: GovernToolOptions,
        tool_name: str = DEFAULT_TOOL_NAME,
    ) -> None:
        self._executor = executor
        self._tool_name = tool_name
        # A single-request side-channel for the CancellationToken execute_code_blocks() was
        # called with: govern_tool()'s ToolDefinition.execute is a plain `Callable[[Mapping[str,
        # Any]], Any]` with no room for a second, non-classifier-relevant argument, so the token
        # for the call currently in flight is stashed here rather than threaded through args
        # (which would put a non-serializable object in front of the classifier for no reason).
        # execute_code_blocks() clears this in a finally-block, so a GovernedCodeExecutor is not
        # safe to call reentrantly/concurrently from two coroutines at once -- the same
        # constraint the real per-instance CodeExecutor implementations already have (a shared
        # work_dir, a shared Jupyter kernel, etc.), so this does not narrow existing usage.
        self._active_token: Optional[CancellationToken] = None

        def _execute(args: Mapping[str, Any]) -> CodeResult:
            block = CodeBlock(code=args["code"], language=args["language"])
            token = self._active_token if self._active_token is not None else CancellationToken()
            return run_coroutine_sync(self._executor.execute_code_blocks([block], token))

        self._governed = govern_tool(ToolDefinition(name=tool_name, execute=_execute), options)

    async def execute_code_blocks(
        self, code_blocks: List[CodeBlock], cancellation_token: CancellationToken
    ) -> CodeResult:
        """Gates and executes each code block in order. Raises
        ``toolgovern.ToolGovernDenialError`` on the first block a rule denies (or a
        require-approval decision resolves to deny) -- no block at or after that point reaches
        the wrapped executor. Otherwise behaves like the wrapped executor's own
        ``execute_code_blocks()``: stops at the first block with a nonzero exit code, and returns
        a combined result across every block that actually ran.
        """
        self._active_token = cancellation_token
        try:
            results: List[CodeResult] = []
            for block in code_blocks:
                args = {"code": block.code, "language": block.language}
                result = self._governed.execute(args)
                results.append(result)
                if result.exit_code != 0:
                    break
            return _combine_results(results)
        finally:
            self._active_token = None

    async def start(self) -> None:
        await self._executor.start()

    async def stop(self) -> None:
        await self._executor.stop()

    async def restart(self) -> None:
        await self._executor.restart()


def _combine_results(results: List[CodeResult]) -> CodeResult:
    """Combines the per-block results ``execute_code_blocks()`` gathered into one ``CodeResult``,
    the same shape the wrapped executor's own (un-governed) batch call would have returned.

    Concatenates ``output`` across every block that ran and takes the last block's ``exit_code``
    (0 unless gating stopped early on a failure, in which case that block's nonzero code).
    ``dataclasses.replace()`` is used rather than constructing a bare ``CodeResult`` so that a
    subclass with extra fields (e.g. ``CommandLineCodeResult.code_file``) keeps those fields --
    from the *last* block that ran, which is an honest, minor divergence from
    ``LocalCommandLineCodeExecutor``'s own batch behavior (it reports the *first* block's
    ``code_file``); this does not affect ``exit_code``/``output``, the fields callers actually
    branch on.
    """
    if not results:
        return CodeResult(exit_code=0, output="")
    if len(results) == 1:
        return results[0]
    combined_output = "".join(r.output for r in results)
    return dataclasses.replace(results[-1], output=combined_output)
