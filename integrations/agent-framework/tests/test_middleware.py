"""Real tests for ToolGovernFunctionMiddleware.

FunctionMiddleware.process(context, call_next) is directly unit-testable without any chat
client / model in the loop -- this mirrors how agent_framework's own middleware tests (and its
own PolicyEnforcementFunctionMiddleware) are exercised. These tests construct real
agent_framework.FunctionTool / FunctionInvocationContext objects and drive the real
ToolGovernFunctionMiddleware.process() against them.
"""

from __future__ import annotations

import pytest
from agent_framework import Content, FunctionInvocationContext, FunctionTool, MiddlewareTermination
from toolgovern import Policy, ResolvePendingInput, ScopeDeclaration

from toolgovern_integration_agent_framework import ToolGovernFunctionMiddleware


def _tool(name: str) -> FunctionTool:
    def _impl(**kwargs):
        return "unused -- call_next is stubbed in these tests"

    return FunctionTool(name=name, description="", func=_impl)


def _context(tool: FunctionTool, args: dict, *, call_id: str = "call-1") -> FunctionInvocationContext:
    ctx = FunctionInvocationContext(function=tool, arguments=args)
    ctx.metadata["call_id"] = call_id
    return ctx


@pytest.mark.asyncio
async def test_allowed_call_proceeds_to_call_next():
    middleware = ToolGovernFunctionMiddleware(Policy(scope=ScopeDeclaration(), agent_id="a"))
    tool = _tool("run_shell")
    context = _context(tool, {"command": "ls -la"})

    called = {"count": 0}

    async def call_next():
        called["count"] += 1

    await middleware.process(context, call_next)

    assert called["count"] == 1
    assert context.result is None


@pytest.mark.asyncio
async def test_denied_call_never_reaches_call_next():
    middleware = ToolGovernFunctionMiddleware(Policy(scope=ScopeDeclaration(), agent_id="a"))
    tool = _tool("run_shell")
    context = _context(tool, {"command": "rm -rf /"})

    called = {"count": 0}

    async def call_next():
        called["count"] += 1

    with pytest.raises(MiddlewareTermination):
        await middleware.process(context, call_next)

    assert called["count"] == 0
    assert context.result is not None
    assert context.result["error"] == "toolgovern denied this tool call."
    assert "TG01-rm-rf" in context.result["rule_fired"]


@pytest.mark.asyncio
async def test_require_approval_surfaces_a_real_function_approval_request():
    """A write outside the declared filesystem scope is require-approval, not deny -- this must
    surface through Agent Framework's OWN function_approval_request content type, not a bespoke
    toolgovern-specific shape."""
    middleware = ToolGovernFunctionMiddleware(
        Policy(scope=ScopeDeclaration(filesystem=["/workspace"]), agent_id="a")
    )
    tool = _tool("write_file")
    context = _context(tool, {"path": "/tmp/output.txt", "operation": "write"}, call_id="call-42")

    async def call_next():
        raise AssertionError("call_next must not run before approval is granted")

    with pytest.raises(MiddlewareTermination):
        await middleware.process(context, call_next)

    assert context.result is not None
    assert isinstance(context.result, Content)
    assert context.result.type == "function_approval_request"
    assert context.result.id == "call-42"
    assert context.result.function_call.name == "write_file"
    pending_id = context.result.additional_properties["toolgovern_pending_id"]
    assert middleware._registry.get(pending_id) is not None
    assert middleware._registry.get(pending_id).status == "pending"


@pytest.mark.asyncio
async def test_approving_the_pending_request_lets_the_real_call_through():
    middleware = ToolGovernFunctionMiddleware(
        Policy(scope=ScopeDeclaration(filesystem=["/workspace"]), agent_id="a")
    )
    tool = _tool("write_file")
    args = {"path": "/tmp/output.txt", "operation": "write"}
    context = _context(tool, args, call_id="call-99")

    async def call_next_deny():
        raise AssertionError("call_next must not run before approval is granted")

    with pytest.raises(MiddlewareTermination):
        await middleware.process(context, call_next_deny)

    approval_request = context.result
    assert approval_request.type == "function_approval_request"

    # Simulate Agent Framework replaying the SAME call with a human-approved response --
    # exactly what _auto_invoke_function() does with an approved function_approval_response.
    approval_response = approval_request.to_function_approval_response(approved=True)
    resumed_context = _context(tool, args, call_id="call-99")
    resumed_context.metadata["approval_response"] = approval_response

    ran = {"count": 0}

    async def call_next_allow():
        ran["count"] += 1

    await middleware.process(resumed_context, call_next_allow)

    assert ran["count"] == 1
    assert resumed_context.result is None


@pytest.mark.asyncio
async def test_denying_the_pending_request_fails_closed():
    middleware = ToolGovernFunctionMiddleware(
        Policy(scope=ScopeDeclaration(filesystem=["/workspace"]), agent_id="a")
    )
    tool = _tool("write_file")
    args = {"path": "/tmp/output.txt", "operation": "write"}
    context = _context(tool, args, call_id="call-7")

    async def call_next_noop():
        raise AssertionError("must not be called before resolution")

    with pytest.raises(MiddlewareTermination):
        await middleware.process(context, call_next_noop)

    approval_request = context.result
    approval_response = approval_request.to_function_approval_response(approved=False)
    resumed_context = _context(tool, args, call_id="call-7")
    resumed_context.metadata["approval_response"] = approval_response

    async def call_next_must_not_run():
        raise AssertionError("a denied approval must never reach call_next")

    with pytest.raises(MiddlewareTermination):
        await middleware.process(resumed_context, call_next_must_not_run)

    assert resumed_context.result["error"] == "toolgovern denied this tool call."


@pytest.mark.asyncio
async def test_pending_approval_is_resolvable_out_of_band_via_the_shared_registry():
    """A caller who supplies their own PendingApprovalRegistry (e.g. one also wired into
    govern_tool()'s own pending_approvals option, or resolved from a webhook/CLI) can resolve
    the SAME entry the middleware registered -- proving this is toolgovern's real durable
    registry, not an internal-only side channel."""
    from toolgovern import PendingApprovalRegistry

    registry = PendingApprovalRegistry()
    middleware = ToolGovernFunctionMiddleware(
        Policy(scope=ScopeDeclaration(filesystem=["/workspace"]), agent_id="a"),
        pending_approvals=registry,
    )
    tool = _tool("write_file")
    context = _context(tool, {"path": "/tmp/output.txt", "operation": "write"}, call_id="call-out-of-band")

    async def call_next_noop():
        raise AssertionError

    with pytest.raises(MiddlewareTermination):
        await middleware.process(context, call_next_noop)

    pending_id = context.result.additional_properties["toolgovern_pending_id"]

    # Resolved directly against the shared registry -- not through the middleware at all.
    outcome = registry.resolve_pending(pending_id, ResolvePendingInput(decision="allow", approved_by="reviewer@example.com"))
    assert outcome.status == "resolved"
    assert outcome.final_decision == "allow"
    assert outcome.approved_by == "reviewer@example.com"
