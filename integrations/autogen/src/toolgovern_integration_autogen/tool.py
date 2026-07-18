"""``governed_autogen_tool()`` -- wraps a real AutoGen ``Tool`` (any ``BaseTool``/``FunctionTool``,
or a hand-rolled implementation of the ``autogen_core.tools.Tool`` protocol) so every call is
classified by toolgovern *before* the tool's real ``run()`` executes.

Every AutoGen tool-execution call site funnels through the same one method:
``Tool.run_json(args, cancellation_token, call_id=None)``. Confirmed by reading the real
installed package: ``autogen_core.tool_agent.ToolAgent.handle_function_call()``
(``autogen_core/tool_agent/_tool_agent.py``) calls ``tool.run_json(args=arguments,
cancellation_token=ctx.cancellation_token, call_id=message.id)`` directly, and
``autogen_core.tools.BaseTool.run_json()`` (``autogen_core/tools/_base.py``) is itself the one
place a ``FunctionTool``'s ``args_type().model_validate(args)`` + ``self.run(...)`` call happens.
Wrapping at ``run_json()`` therefore covers both ``ToolAgent``'s direct-dispatch path and
``AssistantAgent``'s own tool-calling path without forking either one -- the same "one real
dispatch call site, wrapped once" philosophy the LangGraph.js adapter uses
(``integrations/langgraph/src/index.ts``'s ``governedLangGraphTool()``, which wraps the tool's
real ``.invoke()``).

This is a second, complementary integration point to ``GovernedCodeExecutor``
(``code_executor.py``): where that module gates the ``code`` string an executor is about to run,
this one gates the *arguments* any other AutoGen tool (a file-write tool, an HTTP-fetch tool, a
shell tool built as a plain ``FunctionTool`` instead of going through a ``CodeExecutor`` at all)
is about to be called with. A ``url`` argument pointing at a loopback/RFC1918/link-local/cloud-
metadata address is denied by TG03 before the wrapped tool's real ``run()`` -- and therefore
whatever HTTP client it uses -- ever fires, the same SSRF class
`microsoft/autogen#7706 <https://github.com/microsoft/autogen/pull/7706>`_ patches natively
inside AutoGen Studio's ``fetch_webpage`` tool.
"""

from __future__ import annotations

from typing import Any, List, Mapping, Optional, Sequence, Type

from autogen_core import CancellationToken
from autogen_core.tools import Tool, ToolSchema
from pydantic import BaseModel
from toolgovern import GovernToolOptions, ToolDefinition, govern_tool

from ._sync_bridge import run_coroutine_sync

__all__ = ["governed_autogen_tool", "governed_autogen_tools"]


class _GovernedTool:
    """Implements the ``autogen_core.tools.Tool`` protocol by delegating every read-only
    descriptor (``name``/``description``/``schema``/``args_type``/...) to the wrapped tool
    unchanged, and routing ``run_json()`` through toolgovern's classifier first. A plain class
    satisfying the ``Tool`` ``Protocol`` (rather than subclassing ``BaseTool``) is deliberate: it
    keeps this wrapper from re-implementing or depending on ``BaseTool``'s own
    ``args_type().model_validate()`` machinery, delegating that fully to the inner tool exactly
    as it already works today.
    """

    def __init__(self, tool: Tool, options: GovernToolOptions) -> None:
        self._tool = tool
        # Same single-request side-channel pattern as GovernedCodeExecutor, and for the same
        # reason: govern_tool()'s ToolDefinition.execute only receives the classifier-relevant
        # `args` mapping, not the CancellationToken/call_id run_json() was actually invoked with.
        self._active_token: Optional[CancellationToken] = None
        self._active_call_id: Optional[str] = None

        def _execute(args: Mapping[str, Any]) -> Any:
            token = self._active_token if self._active_token is not None else CancellationToken()
            return run_coroutine_sync(self._tool.run_json(args, token, self._active_call_id))

        self._governed = govern_tool(ToolDefinition(name=tool.name, execute=_execute), options)

    @property
    def name(self) -> str:
        return self._tool.name

    @property
    def description(self) -> str:
        return self._tool.description

    @property
    def schema(self) -> ToolSchema:
        return self._tool.schema

    def args_type(self) -> Type[BaseModel]:
        return self._tool.args_type()

    def return_type(self) -> Type[Any]:
        return self._tool.return_type()

    def state_type(self) -> Optional[Type[BaseModel]]:
        return self._tool.state_type()

    def return_value_as_string(self, value: Any) -> str:
        return self._tool.return_value_as_string(value)

    async def run_json(
        self,
        args: Mapping[str, Any],
        cancellation_token: CancellationToken,
        call_id: Optional[str] = None,
    ) -> Any:
        """Classifies ``args`` before the wrapped tool's real ``run_json()`` (and therefore its
        real ``run()``) executes. Raises ``toolgovern.ToolGovernDenialError`` on a ``deny``
        decision -- the wrapped tool's ``run()`` is never called in that case. An ``allow``
        decision runs the real tool and returns its real result unchanged.
        """
        self._active_token = cancellation_token
        self._active_call_id = call_id
        try:
            return self._governed.execute(dict(args))
        finally:
            self._active_token = None
            self._active_call_id = None

    async def save_state_json(self) -> Mapping[str, Any]:
        return await self._tool.save_state_json()

    async def load_state_json(self, state: Mapping[str, Any]) -> None:
        await self._tool.load_state_json(state)


def governed_autogen_tool(tool: Tool, options: GovernToolOptions) -> Tool:
    """Wraps one AutoGen ``Tool`` so every ``run_json()`` call is evaluated by toolgovern's
    classifier before the tool's real ``run()`` executes. The returned object is a drop-in
    replacement anywhere a ``Tool`` is expected -- a ``ToolAgent(tools=[...])`` list, an
    ``AssistantAgent(tools=[...])`` list, or a direct ``run_json()`` call -- since it implements
    the same ``name``/``description``/``schema``/``run_json`` surface the real tool did.

    A ``deny`` decision raises ``ToolGovernDenialError`` from inside ``run_json()`` -- callers see
    it exactly as any other exception a tool call can raise, never a silent no-op.
    """
    return _GovernedTool(tool, options)


def governed_autogen_tools(tools: Sequence[Tool], options: GovernToolOptions) -> List[Tool]:
    """Wraps a whole list of ``Tool``\\ s with the same ``GovernToolOptions`` -- the common case,
    since both ``ToolAgent`` and ``AssistantAgent`` take a ``tools`` list. Call
    ``governed_autogen_tool`` directly per tool if different tools need different scopes."""
    return [governed_autogen_tool(t, options) for t in tools]
