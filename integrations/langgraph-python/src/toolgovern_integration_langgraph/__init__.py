"""``integrations/langgraph-python`` -- routes real ``langchain-ai/langgraph`` (Python) tool calls
through toolgovern's ``govern_tool()`` gate before they execute.

Why this package exists (and why it is not just a copy of ``integrations/langgraph``, the
LangGraph.js adapter)
----------------------------------------------------------------------------------------------
``integrations/langgraph`` targets LangGraph.js (``langchain-ai/langgraphjs``). Its own docstring
explains why it wraps at tool-definition time instead of inside ``ToolNode``: the JS package's
``ToolNode`` constructor only accepts ``{name, tags, handleToolErrors}`` -- there is no
interception hook inside the node itself.

``langchain-ai/langgraph`` (the separately maintained Python package) is different. Confirmed by
reading the real, installed ``langgraph.prebuilt.tool_node`` source (``langgraph==1.2.9``,
``langgraph-prebuilt==1.1.0`` at the time this was written):

    class ToolNode(RunnableCallable):
        def __init__(
            self,
            tools: Sequence[BaseTool | Callable],
            *,
            ...
            wrap_tool_call: ToolCallWrapper | None = None,
            awrap_tool_call: AsyncToolCallWrapper | None = None,
        ) -> None: ...

    ToolCallWrapper = Callable[
        [ToolCallRequest, Callable[[ToolCallRequest], ToolMessage | Command]],
        ToolMessage | Command,
    ]

``wrap_tool_call`` is a first-class, public constructor parameter of ``ToolNode`` -- not a private
attribute, not something reached by monkey-patching. It is invoked once per dispatched tool call,
receives a ``ToolCallRequest`` (the tool call, the resolved ``BaseTool`` or ``None``, the graph
``state``, and a ``ToolRuntime``/``Runtime``), and an ``execute`` callable that actually runs the
tool -- callable more than once, for retries. Every real LangGraph GitHub issue this project has
validated (langchain-ai/langgraph #8026, #7687, #7178, #8169) is filed against exactly this
package, so this is the integration point that structurally matters. See ``docs/root-cause.md``
in this package's directory for the per-issue verdicts.

This package therefore exposes two entry points, both wrapping ``toolgovern.govern_tool()`` --
never LangGraph internals -- underneath:

1. ``governed_wrap_tool_call(options)`` -- builds a ``wrap_tool_call`` callable for
   ``ToolNode(tools, wrap_tool_call=...)``. One classifier gate, applied uniformly to every tool a
   ``ToolNode`` dispatches, with access to the call's live graph ``state``/``runtime`` (e.g. to
   derive ``session_id`` from a thread id in ``RunnableConfig``) that a tool-definition-time wrap
   never sees. This is the primary, LangGraph-native entry point this package exists to provide.

2. ``governed_tool(tool, options)`` / ``governed_tools(tools, options)`` -- the same
   tool-definition-boundary wrapping ``integrations/langgraph`` (JS) uses: wrap each
   ``BaseTool`` with ``govern_tool()``, then re-wrap the governed callable with LangChain's own
   ``StructuredTool.from_function`` (a fully public API) so the result is still a real
   ``BaseTool``. Useful when tools are handed to ``create_react_agent(..., tools=...)`` or
   ``bind_tools()`` directly, without constructing a custom ``ToolNode``.

Both routes call the identical ``toolgovern.govern_tool()`` gate. Neither monkey-patches
``ToolNode``, ``BaseTool``, or any LangChain/LangGraph internal.

A ``deny`` decision raises ``toolgovern.ToolGovernDenialError`` from inside the wrapped
execution path, and the underlying tool never executes -- confirmed both by reading
``ToolNode._run_one()``'s ``try/except`` around ``self._wrap_tool_call(...)`` and by this
package's own tests. What that exception turns INTO by the time it reaches your graph's caller
depends on how ``handle_tool_errors`` is configured on the ``ToolNode`` -- verified against the
currently installed ``langgraph==1.2.9``:

- ``ToolNode``'s own DEFAULT (``_default_handle_tool_errors``, used when ``handle_tool_errors`` is
  left unset) only recognizes LangChain's own ``ToolInvocationError`` and re-raises everything
  else -- so with no explicit configuration, ``ToolGovernDenialError`` propagates out of the graph
  invocation as a raised exception, not an error ``ToolMessage``. This is a genuinely different,
  newer default than older LangGraph releases; a caller should not assume denials silently become
  chat-visible error messages without checking this.
- Passing ``handle_tool_errors=True`` (the bool literal) explicitly makes ``ToolNode`` catch
  ``ToolGovernDenialError`` (like any other ``Exception``) and convert it into a ``ToolMessage``
  with ``status="error"``, so the agent loop sees a normal tool-error turn instead of a crash.

Either way, the safety invariant this package exists for holds: the real tool body never runs on a
denied call. Only the *shape* of the failure the rest of your graph observes differs, and that
shape is controlled by your own ``handle_tool_errors`` choice, not by this package.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable, List, Mapping, Optional, Sequence, Union

from langchain_core.tools import BaseTool, StructuredTool
from langchain_core.messages import ToolMessage
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.tool_node import ToolCallRequest, ToolCallWrapper
from langgraph.types import Command

from toolgovern import GovernToolOptions, ToolDefinition, ToolGovernDenialError, govern_tool

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "governed_wrap_tool_call",
    "governed_tool_node",
    "governed_tool",
    "governed_tools",
    "GovernToolOptions",
    "ToolGovernDenialError",
]

# Re-exported so a caller of this package never needs a second `import toolgovern` just to build
# the `options` argument these functions take.
GovernToolOptions = GovernToolOptions
ToolGovernDenialError = ToolGovernDenialError


def governed_wrap_tool_call(
    options: GovernToolOptions,
    *,
    session_id_from_runtime: Optional[Callable[[Any], Optional[str]]] = None,
    agent_id_from_runtime: Optional[Callable[[Any], Optional[str]]] = None,
) -> ToolCallWrapper:
    """Builds a ``wrap_tool_call`` callable for ``ToolNode(tools, wrap_tool_call=...)``.

    Every tool call the resulting ``ToolNode`` dispatches is routed through toolgovern's real
    classifier (via ``govern_tool()``) before LangGraph's own ``execute()`` ever runs the tool.
    The tool name gated is ``request.tool_call["name"]`` -- the actual name the model requested,
    whether or not ``request.tool`` resolved to a registered ``BaseTool`` (an unregistered-tool
    call is still classified and, if allowed, still fails LangGraph's own validation exactly as it
    would with no wrapper at all -- this gate adds a check, it never loosens LangGraph's own).

    ``session_id_from_runtime`` / ``agent_id_from_runtime`` are optional hooks that receive the
    call's ``ToolRuntime`` (``request.runtime`` -- has ``.config``, ``.state``, ``.context``,
    ``.tool_call_id``) and may return a per-call override, e.g. deriving ``session_id`` from
    ``runtime.config["configurable"]["thread_id"]`` so trace entries and scope lookups key off the
    real LangGraph thread rather than one static id for every call. Returning ``None`` (or omitting
    the hook) keeps ``options.session_id`` / ``options.agent_id`` unchanged -- this is opt-in,
    never a behavior change for callers who do not need it.

    A ``deny`` decision raises ``ToolGovernDenialError`` from inside this wrapper; with
    ``ToolNode``'s default ``handle_tool_errors=True`` that becomes an error ``ToolMessage``, never
    a silent skip.
    """

    def wrapper(
        request: ToolCallRequest,
        execute: Callable[[ToolCallRequest], Union[ToolMessage, Command]],
    ) -> Union[ToolMessage, Command]:
        tool_name = request.tool_call["name"]
        call_args: Mapping[str, Any] = request.tool_call.get("args") or {}

        effective_options = options
        overrides: dict = {}
        if session_id_from_runtime is not None:
            derived_session = session_id_from_runtime(request.runtime)
            if derived_session:
                overrides["session_id"] = derived_session
        if agent_id_from_runtime is not None:
            derived_agent = agent_id_from_runtime(request.runtime)
            if derived_agent:
                overrides["agent_id"] = derived_agent
        if overrides:
            effective_options = replace(options, **overrides)

        def _execute(effective_args: Mapping[str, Any]) -> Union[ToolMessage, Command]:
            # Re-enter LangGraph's own execute() (validation, injected-state args, Command
            # handling all still apply) with whatever args the classifier/gate settled on --
            # normally unchanged, but this is also the seam a future retry/edit path would use.
            modified_call = {**request.tool_call, "args": dict(effective_args)}
            inner_request = request.override(tool_call=modified_call)
            return execute(inner_request)

        gated = govern_tool(ToolDefinition(name=tool_name, execute=_execute), effective_options)
        return gated.execute(call_args)

    return wrapper


def governed_tool_node(
    tools: Sequence[Union[BaseTool, Callable]],
    options: GovernToolOptions,
    *,
    session_id_from_runtime: Optional[Callable[[Any], Optional[str]]] = None,
    agent_id_from_runtime: Optional[Callable[[Any], Optional[str]]] = None,
    **tool_node_kwargs: Any,
) -> ToolNode:
    """Convenience constructor: ``ToolNode(tools, wrap_tool_call=governed_wrap_tool_call(...))``
    in one call. Any additional ``ToolNode`` kwargs (``name``, ``tags``, ``handle_tool_errors``,
    ``messages_key``) pass through unchanged.
    """
    wrap_tool_call = governed_wrap_tool_call(
        options,
        session_id_from_runtime=session_id_from_runtime,
        agent_id_from_runtime=agent_id_from_runtime,
    )
    return ToolNode(tools, wrap_tool_call=wrap_tool_call, **tool_node_kwargs)


def governed_tool(tool: BaseTool, options: GovernToolOptions) -> BaseTool:
    """Wraps one LangChain ``BaseTool`` so every invocation is evaluated by toolgovern's
    classifier before the tool's real ``.invoke()`` runs -- the same tool-definition-boundary
    wrapping ``integrations/langgraph`` (the LangGraph.js adapter) uses, ported to a real
    ``BaseTool``. The returned tool keeps the original name, description, and schema, so it is a
    drop-in replacement anywhere a LangChain ``BaseTool`` is expected: a ``ToolNode`` tools array
    (without needing ``wrap_tool_call`` at all), a ``bind_tools()`` call, or
    ``create_react_agent(..., tools=...)``.

    Prefer ``governed_wrap_tool_call`` / ``governed_tool_node`` when building a ``ToolNode``
    directly -- it gates every tool with one wrapper and sees the call's live graph state/runtime.
    Use ``governed_tool`` when tools are handed to something that does not expose a
    ``wrap_tool_call`` seam.
    """
    raw = ToolDefinition(name=tool.name, execute=lambda args: tool.invoke(dict(args)))
    gated = govern_tool(raw, options)

    def _run(**kwargs: Any) -> Any:
        return gated.execute(kwargs)

    return StructuredTool.from_function(
        func=_run,
        name=tool.name,
        description=tool.description or f"{tool.name} tool",
        args_schema=tool.args_schema,
    )


def governed_tools(tools: Sequence[BaseTool], options: GovernToolOptions) -> List[BaseTool]:
    """Wraps a whole sequence of tools with ``governed_tool`` in one call -- every tool shares the
    same ``GovernToolOptions`` (same agent identity, scope, and trace); call ``governed_tool``
    directly per tool if different tools need different scopes."""
    return [governed_tool(t, options) for t in tools]
