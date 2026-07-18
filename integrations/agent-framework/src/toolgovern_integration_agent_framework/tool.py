"""``governed_function_tool()`` -- wrap a plain Python callable in a real
``agent_framework.FunctionTool`` whose body is gated by toolgovern's ``govern_tool()``.

This is the tool-definition-time integration point: it does not fork or monkey-patch
``agent_framework`` at all. It builds a toolgovern ``ToolDefinition`` around the caller's
function, runs it through ``govern_tool()`` (exactly as any other toolgovern integration would),
and wraps the *gated* callable -- not the original one -- in a real ``FunctionTool``. Every path
that can reach the real function body (a direct ``await tool.invoke(...)`` call, the framework's
own function-calling loop, or anything else that ends up calling the tool) goes through
toolgovern's classifier first, because the gate is baked into the callable itself, not bolted on
at a call site the caller might route around.

This is deliberately a second, independent layer under Agent Framework's own ``approval_mode``
gate, not a replacement for it -- see ``middleware.py`` for the per-call, classifier-driven layer
that surfaces a require-approval decision through Agent Framework's own
``function_approval_request``/``function_approval_response`` flow. The two compose: an
``approval_mode="always_require"`` tool built with this wrapper still gets toolgovern's
allow/deny/require-approval verdict evaluated on every call, in addition to whatever Agent
Framework's own approval flow decides.

One confirmed real gap this layering pays for: as of ``agent-framework`` 1.11.0 on PyPI,
``FunctionTool.invoke()`` does not itself check ``approval_mode`` at all -- that check exists
only in the function-calling loop's ``_try_execute_function_calls()``, so a caller who invokes
``tool.invoke()`` directly (bypassing the loop) skips Agent Framework's own approval gate
entirely. A fix for this was proposed upstream in
https://github.com/microsoft/agent-framework/pull/5494, but that PR was closed without being
merged (see this package's README, "Upstream issues investigated"). Wrapping a tool with
``governed_function_tool()`` is unaffected by that specific gap: toolgovern's gate lives inside
the wrapped callable's own body, so ``tool.invoke()`` called directly still runs the classifier
before the real function executes, deny or require-approval verdicts included.
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Literal, Mapping, Optional

from agent_framework import FunctionTool
from pydantic import BaseModel
from toolgovern import GovernToolOptions, ToolDefinition, govern_tool

__all__ = ["governed_function_tool"]

# agent_framework.FunctionTool's own `approval_mode` type. Not re-exported at the top level of
# `agent_framework` (it is a private TypeAlias in `agent_framework._tools`), so it is restated
# here rather than importing a private symbol -- the two Literal values are part of FunctionTool's
# public constructor signature and documented in its own docstring.
ApprovalMode = Literal["always_require", "never_require"]


def governed_function_tool(
    func: Callable[..., Any],
    options: GovernToolOptions,
    *,
    name: Optional[str] = None,
    description: Optional[str] = None,
    input_model: Optional[type[BaseModel] | Mapping[str, Any]] = None,
    approval_mode: Optional[ApprovalMode] = None,
    kind: Optional[str] = None,
    **function_tool_kwargs: Any,
) -> FunctionTool:
    """Wrap ``func`` so every real invocation is evaluated by toolgovern's classifier first.

    Args:
        func: The real tool implementation. Called with keyword arguments matching its own
            signature -- exactly as Agent Framework would call it directly, since this wrapper
            preserves ``func``'s signature (via ``functools.wraps``) for schema inference.
        options: A toolgovern ``GovernToolOptions`` (or ``GovernToolOptions.from_policy(policy)``)
            describing the declared scope, rule overrides, and optional trace/approval wiring for
            this tool. The same options object toolgovern's own ``govern_tool()`` accepts.

    Keyword Args:
        name: Tool name. Defaults to ``func.__name__``.
        description: Tool description shown to the model. Defaults to ``func.__doc__`` or "".
        input_model: Optional explicit Pydantic model or JSON-schema mapping for the tool's
            parameters. When omitted, Agent Framework infers it from ``func``'s own signature
            (this wrapper's ``functools.wraps`` makes that inference see the real parameters,
            not the wrapper's own ``**kwargs`` signature).
        approval_mode: Agent Framework's own ``approval_mode`` ("always_require" /
            "never_require"). This is independent of toolgovern's per-call decision -- see the
            module docstring. Defaults to Agent Framework's own default (never_require).
        kind: Optional Agent Framework tool-kind classification (e.g. "shell").
        **function_tool_kwargs: Any other keyword argument ``agent_framework.FunctionTool``
            accepts (``max_invocations``, ``result_parser``, ``additional_properties``, ...).

    Returns:
        A real ``agent_framework.FunctionTool``. Calling it (directly via ``tool.invoke()``, or
        through an agent's function-calling loop) with arguments the classifier denies raises
        ``toolgovern.ToolGovernDenialError`` from inside the tool's own callable -- Agent
        Framework's own exception handling around a raised tool call then applies exactly as it
        would for any other exception a tool implementation raises.
    """
    tool_name = name or getattr(func, "__name__", None)
    if not tool_name:
        raise ValueError("governed_function_tool() requires a name (func has no __name__).")

    def _execute(args: Mapping[str, Any]) -> Any:
        return func(**args)

    gated = govern_tool(ToolDefinition(name=tool_name, execute=_execute), options)

    @functools.wraps(func)
    def _governed_call(**kwargs: Any) -> Any:
        return gated.execute(kwargs)

    # functools.wraps() copies __wrapped__, __name__, __doc__, __annotations__ from func onto
    # _governed_call, so FunctionTool's schema inference (inspect.signature() + get_type_hints())
    # sees func's real parameters, not _governed_call's own **kwargs signature -- see
    # test_tool.py::test_multi_parameter_schema_is_inferred_from_the_real_function, which
    # exercises this path with a multi-parameter, typed function.

    return FunctionTool(
        name=tool_name,
        description=description if description is not None else (func.__doc__ or ""),
        func=_governed_call,
        input_model=input_model,
        approval_mode=approval_mode,
        kind=kind,
        **function_tool_kwargs,
    )
