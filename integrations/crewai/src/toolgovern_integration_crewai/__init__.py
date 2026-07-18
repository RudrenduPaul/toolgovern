"""toolgovern-integration-crewai -- routes CrewAI tool calls through toolgovern's
``govern_tool()`` gate before a tool's real ``_run()`` ever fires.

Ported by hand from ``integrations/langgraph/src/index.ts``'s wrapping philosophy: no
monkey-patching of CrewAI internals, wrap at the public tool-definition boundary instead.

IMPORTANT -- confirmed by reading the real ``crewai`` 1.15.4 wheel installed via
``pip install crewai`` (``crewai/tools/base_tool.py``), not assumed from memory or an older
release:

- ``BaseTool`` is a Pydantic ``BaseModel`` (``ABC``) with an abstract ``_run(*args, **kwargs)``
  a subclass must implement, and a concrete ``run(*args, **kwargs)`` that validates keyword
  arguments against ``args_schema``, claims a usage-count slot, then calls ``self._run(...)``
  (awaiting it first if it returned a coroutine).
- There IS a ``before_tool_call`` hook system in this version
  (``crewai.hooks.register_before_tool_call_hook`` / the ``@before_tool_call`` decorator, see
  ``crewai/hooks/tool_hooks.py`` and ``crewai/hooks/decorators.py``), plus an open PR (#6432)
  proposing a ``GuardrailProvider`` adapter on top of it. That hook system is a *global*,
  process-wide registry keyed by tool/agent name patterns -- fundamentally different from
  ``govern_tool()``'s per-tool-instance, per-agent-identity, per-scope gate. Wrapping at the
  ``BaseTool`` boundary (this module's approach) composes with that hook system rather than
  replacing it, mirrors the already-shipped LangGraph.js adapter's own reasoning (wrap at the
  public tool-definition boundary, not a framework's internal hook plumbing), and works
  identically across every CrewAI construct that ultimately holds a ``BaseTool`` instance --
  a plain ``Tool``, a ``@tool``-decorated function, an MCP-backed tool
  (``MCPToolWrapper``/``MCPNativeTool`` both subclass ``BaseTool`` too, confirmed by reading
  ``crewai/tools/mcp_tool_wrapper.py`` and ``crewai/tools/mcp_native_tool.py``), or any other
  ``BaseTool`` subclass a user or third-party package defines.

Usage:

    from crewai_tools import CodeInterpreterTool
    from toolgovern import GovernToolOptions, ScopeDeclaration
    from toolgovern_integration_crewai import governed_crewai_tool

    governed = governed_crewai_tool(
        CodeInterpreterTool(),
        GovernToolOptions(
            scope=ScopeDeclaration(network=False, filesystem=["./workspace"]),
            agent_id="research-sub",
        ),
    )
    agent = Agent(..., tools=[governed])
"""

from __future__ import annotations

from typing import Any, Mapping

from crewai.tools import BaseTool
from pydantic import ConfigDict, PrivateAttr
from toolgovern import GovernToolOptions, ToolDefinition, ToolGovernDenialError, govern_tool

__version__ = "0.1.0"


class GovernedCrewAITool(BaseTool):
    """A ``BaseTool`` that wraps another ``BaseTool`` instance so every real invocation is
    evaluated by toolgovern's classifier before the wrapped tool's own ``_run()`` executes.

    Not a monkey-patch: the wrapped tool's class and its ``_run`` method are never modified.
    This is a new ``BaseTool`` instance -- same ``name``, ``description``, and ``args_schema``
    as the tool it wraps -- that CrewAI's ``Agent``/``Crew``/``Task`` machinery cannot
    distinguish from any other tool. A ``deny`` decision raises ``ToolGovernDenialError`` from
    inside this wrapper's ``_run``, before the wrapped tool's ``_run`` is ever called -- the
    same "denied calls never reach the real implementation" guarantee ``govern_tool()`` gives
    every other framework it wraps.

    Construct via ``governed_crewai_tool(tool, options)`` below rather than this class
    directly -- that function is the stable public entry point this package exports.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    _wrapped_tool: BaseTool = PrivateAttr()
    _governed: ToolDefinition = PrivateAttr()

    def __init__(self, tool: BaseTool, options: GovernToolOptions, **kwargs: Any) -> None:
        super().__init__(
            name=tool.name,
            description=tool.description,
            args_schema=tool.args_schema,
            result_schema=tool.result_schema,
            env_vars=tool.env_vars,
            **kwargs,
        )
        self._wrapped_tool = tool

        def _execute(args: Mapping[str, Any]) -> Any:
            # Calls the wrapped tool's own public `run()`, not `_run()` directly -- so the
            # wrapped tool's own kwarg validation, usage-count tracking, and caching still
            # apply exactly as they would if it were never wrapped. `run()` is what actually
            # calls `_run()` internally; a `deny` decision below means this lambda -- and
            # therefore the wrapped tool's `_run()` -- is never reached at all.
            return tool.run(**dict(args))

        raw = ToolDefinition(name=tool.name, execute=_execute)
        self._governed = govern_tool(raw, options)

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        if args:
            raise TypeError(
                f"governed_crewai_tool wrapping '{self.name}': positional arguments are not "
                "supported -- toolgovern's classifier operates on a name->value argument "
                "mapping, and CrewAI's own Agent/Task tool-calling path always calls a tool "
                "with keyword arguments derived from its args_schema. Pass keyword arguments "
                "(matching the wrapped tool's own _run signature) instead."
            )
        return self._governed.execute(kwargs)


def governed_crewai_tool(tool: BaseTool, options: GovernToolOptions) -> BaseTool:
    """Wraps one CrewAI ``BaseTool`` instance so every real invocation is evaluated by
    toolgovern's classifier before the wrapped tool's own ``_run()`` executes.

    ``tool`` must be an already-constructed ``BaseTool`` instance -- a plain ``Tool`` from the
    ``@tool`` decorator, a hand-written ``BaseTool`` subclass instance, an ``MCPToolWrapper``/
    ``MCPNativeTool`` instance, or any other object CrewAI accepts in an ``Agent(tools=[...])``
    list. If you only have a ``BaseTool`` *subclass* (not yet instantiated), instantiate it
    first (``governed_crewai_tool(MyTool(), options)``) -- CrewAI's own tool-execution surface
    is instance-based (``Agent.tools: list[BaseTool]``), so there is no separate class-level
    wrapping to do.

    Returns a new ``BaseTool`` with the same ``name``, ``description``, and ``args_schema`` as
    ``tool`` -- a drop-in replacement anywhere a CrewAI tool is expected (an ``Agent``'s or
    ``Task``'s ``tools`` list). A ``deny`` decision raises ``ToolGovernDenialError`` -- CrewAI's
    own tool-calling path (``ToolUsage``/``CrewStructuredTool``) surfaces an uncaught tool
    exception as a tool-error result fed back to the agent, not a silent pass-through.

    Every tool needs its own ``GovernToolOptions`` (agent identity, declared scope, and any
    shared ``TraceWriter``/``ScopeRegistry``) -- there is no ``governed_crewai_tools(...)``
    plural helper, unlike the LangGraph.js adapter's ``governedLangGraphTools``, because CrewAI
    tools are commonly assigned per-agent with different scopes (a research agent's tools vs. a
    coordinator's), making "wrap this whole list with one shared options object" the wrong
    default here. Call this once per tool.
    """
    return GovernedCrewAITool(tool, options)


__all__ = ["GovernedCrewAITool", "governed_crewai_tool", "__version__"]
