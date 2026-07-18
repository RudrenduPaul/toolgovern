# toolgovern-integration-autogen

Routes real Microsoft AutoGen (`autogen-agentchat` / `autogen-core` / `autogen-ext`) tool and
code-execution calls through [`toolgovern`](https://github.com/RudrenduPaul/toolgovern)'s
`govern_tool()` gate before they reach AutoGen's own executor/tool-dispatch call sites -- the
same "one real dispatch call site, wrapped once" philosophy as
[`toolgovern-integration-langgraph`](../langgraph) (which wraps LangGraph.js's real
`.invoke()`), applied to AutoGen's two real call sites instead.

## Why this exists

`LocalCommandLineCodeExecutor` (`autogen_ext.code_executors.local`) writes LLM-generated code
straight to disk and runs it as a local subprocess. The only existing safeguard is a
`UserWarning` at construction time -- informational, not a runtime control, and silently dropped
by any code that filters Python warnings. That's
[microsoft/autogen#7462](https://github.com/microsoft/autogen/issues/7462), the flagship issue
this package addresses.

## Install

This package is not yet published to PyPI. Install it from source, alongside a real PyPI install
of the toolgovern core it depends on (published as `toolgovern-cli`; the module you import stays
`toolgovern`):

```bash
pip install toolgovern-cli
git clone https://github.com/RudrenduPaul/toolgovern.git
cd toolgovern
pip install -e integrations/autogen
```

This pulls in `toolgovern` (the core governance library) and `autogen-core`/`autogen-agentchat`
as real dependencies. Install whichever `autogen-ext` executor extra you actually use
(`autogen-ext[docker]`, etc.) separately -- it is not a hard dependency of this package, since
which concrete `CodeExecutor` you wrap is your choice.

See [the root toolgovern README](https://github.com/RudrenduPaul/toolgovern) for why runtime
tool-call governance matters right now.

## `GovernedCodeExecutor` -- gate code execution

Wraps any real `CodeExecutor` (`LocalCommandLineCodeExecutor`, `DockerCommandLineCodeExecutor`,
`JupyterCodeExecutor`, ...) so every `CodeBlock` is classified by toolgovern's TG01 (shell/
process risk) and TG02 (filesystem scope) rules before the wrapped executor ever runs it:

```python
from autogen_ext.code_executors.local import LocalCommandLineCodeExecutor
from toolgovern import GovernToolOptions, ScopeDeclaration, ToolGovernDenialError
from toolgovern_integration_autogen import GovernedCodeExecutor

real_executor = LocalCommandLineCodeExecutor(work_dir="./coding")
governed = GovernedCodeExecutor(real_executor, GovernToolOptions(scope=ScopeDeclaration()))

# A benign block runs for real, through the real executor.
result = await governed.execute_code_blocks(
    [CodeBlock(code="print('hi')", language="python")], CancellationToken()
)

# A dangerous one never reaches LocalCommandLineCodeExecutor.execute_code_blocks() at all.
try:
    await governed.execute_code_blocks(
        [CodeBlock(code="import os; os.system('rm -rf /')", language="python")],
        CancellationToken(),
    )
except ToolGovernDenialError as e:
    print(f"denied before execution: {e}")
```

`rm -rf /`, curl-pipe-to-shell, a fork bomb, a reverse shell, chmod 777, and a `"../"`-traversal
`open(..., "w")` are all denied at the classifier level -- regardless of the code block's
declared language -- because toolgovern's `extract_command()`/`extract_path_from_code()` treat a
`code`-named argument as command-like/path-scannable text directly.

## `governed_autogen_tool()` -- gate any other tool call

Wraps any `autogen_core.tools.Tool` (a `FunctionTool`, or a hand-rolled `Tool`) so every
`run_json()` call -- the same dispatch point `autogen_core.tool_agent.ToolAgent` and
`AssistantAgent` both use -- is classified before the tool's real `run()` executes:

```python
from autogen_core.tools import FunctionTool
from toolgovern import GovernToolOptions, ScopeDeclaration
from toolgovern_integration_autogen import governed_autogen_tool

async def fetch_webpage(url: str) -> str:
    ...

tool = FunctionTool(fetch_webpage, description="Fetch a webpage")
governed = governed_autogen_tool(
    tool, GovernToolOptions(scope=ScopeDeclaration(network=["example.com"]))
)

agent = AssistantAgent("researcher", model_client=model_client, tools=[governed])
```

A `url` argument resolving to a loopback/RFC1918/link-local/cloud-metadata address is denied by
TG03 before the wrapped tool's real `run()` (and therefore whatever HTTP client it uses) ever
fires -- the same SSRF class
[microsoft/autogen#7706](https://github.com/microsoft/autogen/pull/7706) patches natively inside
AutoGen Studio's `fetch_webpage` tool.

`governed_autogen_tool()` also composes with toolgovern's `ScopeRegistry` exactly like any other
governed tool: wire `GovernToolOptions(scope_registry=..., coordinator_id=...)` and a sub-agent's
effective scope becomes the intersection of what it requests and what its coordinator's own
scope actually covers -- see `tests/test_tool.py::test_sub_agent_tool_call_is_capped_by_coordinator_scope`
for a full worked example addressing
[microsoft/autogen#7528](https://github.com/microsoft/autogen/issues/7528).

## What this does not do

This is a pre-execution argument/string classifier, not a sandbox, and not a general-purpose
policy-authoring system:

- **No process isolation.** It cannot enforce CPU/memory/wall-clock resource limits or
  filesystem/network namespace isolation. For genuine isolation, wrap
  `DockerCommandLineCodeExecutor` (or a Firecracker/gVisor/WASM executor) instead of
  `LocalCommandLineCodeExecutor` -- the two concerns are complementary. This is a real,
  structural gap, not a missing feature that could be bolted on here: see
  [microsoft/autogen#7230](https://github.com/microsoft/autogen/issues/7230), whose actual ask
  (process/kernel-level resource isolation) an in-process pre-execution gate cannot satisfy
  regardless of how the gate itself is implemented.
- **Fixed rule categories, not arbitrary custom policy.** TG01-TG05 (+TG08) are a fixed classifier,
  not a Rego-like general authorization language -- a policy YAML can disable a rule or downgrade
  it to require-approval, but cannot express arbitrary custom logic the way
  [microsoft/autogen#7524](https://github.com/microsoft/autogen/pull/7524)'s OPA integration can.
- **No env-var scrubbing or rlimits.** The in-process hardening
  [microsoft/autogen#7611](https://github.com/microsoft/autogen/pull/7611) proposed (and which was
  ultimately closed/superseded upstream) -- credential env-var scrubbing, `RLIMIT_CPU`/
  `RLIMIT_AS` on the subprocess -- is out of scope for this adapter; it operates on the code
  *string* before execution, not on the subprocess environment/resource limits during execution.
- **Cross-thread cancellation is best-effort.** See `_sync_bridge.py`'s docstring: the real
  AutoGen call this bridges into runs on a separate worker thread with its own event loop, so a
  `CancellationToken` cancelled from the caller's original loop after the bridged call has
  already started may not interrupt it as promptly as native same-loop cancellation would.

See the toolgovern core's [`docs/security-model.md`](../../docs/security-model.md) for the full,
honest disclosure of the classifier's own known evasion classes (obfuscation techniques already
closed, and the ones still open).

## Development

```bash
cd integrations/autogen
pip install -e "../../python[dev]"   # the toolgovern core, editable
pip install -e ".[dev]"
pytest
```

## License

Apache 2.0 -- see [LICENSE](../../LICENSE).
