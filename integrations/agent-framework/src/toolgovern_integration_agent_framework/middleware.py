"""``ToolGovernFunctionMiddleware`` -- surface a toolgovern require-approval decision through
Agent Framework's OWN ``function_approval_request`` / ``function_approval_response`` flow,
per-call, driven by the real classifier -- not a separate side channel.

Agent Framework's ``FunctionTool.approval_mode`` is a *static*, per-tool switch checked once
(in ``_try_execute_function_calls()``) before any call to that tool ever reaches
``FunctionTool.invoke()``: either every call to the tool requires approval, or none do. It has no
per-call, argument-aware decision of its own. toolgovern's classifier is exactly that: a per-call
verdict (allow / deny / require-approval) based on the actual arguments of *this* call, evaluated
against a declared scope.

This module bridges the two using the same extension point Agent Framework's own security
middleware uses (see ``agent_framework.security.PolicyEnforcementFunctionMiddleware``, whose
``_request_policy_violation_approval()`` does exactly this): a ``FunctionMiddleware`` that runs
BEFORE ``call_next()`` (i.e. before the real tool body executes), classifies the call, and:

- ``allow`` -> ``await call_next()``; the tool executes normally.
- ``deny`` -> sets ``context.result`` to an error payload and raises ``MiddlewareTermination``;
  the tool body never runs.
- ``require-approval`` -> registers the decision in a toolgovern ``PendingApprovalRegistry``
  (the same durable registry Foundation step 2 built for exactly this "a decision needs to
  outlive one in-process callback" case), sets ``context.result`` to a real
  ``Content.from_function_approval_request(...)`` -- the identical content type Agent Framework's
  own approval flow produces -- and raises ``MiddlewareTermination``. The framework's own
  function-calling loop then does whatever it already does with a ``function_approval_request``:
  surface it to whatever is driving the conversation (a UI, ``ToolApprovalMiddleware``,
  a CLI), exactly as if a statically-``always_require`` tool had produced it.
- A later re-invocation of the SAME call carrying a ``function_approval_response`` in
  ``context.metadata["approval_response"]`` (this is how Agent Framework itself replays an
  answered approval back through the middleware pipeline -- see
  ``agent_framework._tools._auto_invoke_function``) is resolved against the pending registry
  entry: approved resolves it "allow" and calls ``call_next()``; denied (or an unrecognized /
  already-resolved / expired pending id) fails closed.

What this deliberately does NOT do: it does not re-implement Agent Framework's own
``ToolApprovalMiddleware`` standing-rule/session-state machinery, and it is not a replacement for
``approval_mode="always_require"`` on tools that should always gate regardless of arguments -- the
two compose (see ``tool.py``'s module docstring). It also does not persist the pending registry
across a process restart; that limitation is toolgovern's own, inherited unchanged (see
``PendingApprovalRegistry``'s own module docstring in the core package).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional

from agent_framework import Content, FunctionInvocationContext, FunctionMiddleware, MiddlewareTermination
from toolgovern import (
    ClassifyOptions,
    Policy,
    PendingApprovalRegistry,
    ResolvePendingInput,
    RuleContext,
    ScopeDeclaration,
    classify,
)

__all__ = ["ToolGovernFunctionMiddleware"]


def _current_arguments(context: FunctionInvocationContext) -> Dict[str, Any]:
    arguments = context.arguments
    if isinstance(arguments, Mapping):
        return dict(arguments)
    # A pydantic BaseModel instance.
    return arguments.model_dump()  # type: ignore[union-attr]


@dataclass(frozen=True)
class _TrackedApproval:
    """What this middleware needs to remember about one call_id awaiting approval: the
    toolgovern pending_id it registered, so a later replay carrying a
    ``function_approval_response`` for the same call_id can be resolved against the right entry.
    """

    pending_id: str


class ToolGovernFunctionMiddleware(FunctionMiddleware):
    """Gate every function invocation through toolgovern's classifier, surfacing a
    require-approval verdict through Agent Framework's own approval-request/response content
    types.

    One instance is stateful across calls within a process (it tracks call_id -> pending_id for
    calls currently awaiting approval), so use one instance per agent/run, not a shared global
    singleton across unrelated agents unless their call_ids are guaranteed not to collide.
    """

    def __init__(
        self,
        policy: Policy,
        *,
        pending_approvals: Optional[PendingApprovalRegistry] = None,
    ) -> None:
        """Initialize the middleware.

        Args:
            policy: The declared scope + rule overrides to classify every call against (the same
                ``Policy`` shape ``govern_tool()`` and ``load_policy()`` use).

        Keyword Args:
            pending_approvals: Durable registry for require-approval decisions. When omitted, a
                private registry scoped to this middleware instance is created -- fine for a
                single process; a caller who needs the pending-approval record visible to a
                webhook/CLI/review-queue running in a different process should supply their own
                shared instance, exactly as with ``govern_tool()``'s own ``pending_approvals``
                option.
        """
        self._policy = policy
        self._registry = pending_approvals or PendingApprovalRegistry()
        self._disabled_rules = list(policy.rules.disable) if policy.rules else []
        self._downgrade_to_approval = list(policy.rules.require_approval) if policy.rules else []
        # call_id -> the toolgovern pending_id registered for that call, while it awaits approval.
        self._tracked: Dict[str, _TrackedApproval] = {}

    def _scope(self) -> ScopeDeclaration:
        return self._policy.scope

    def _call_id(self, context: FunctionInvocationContext) -> str:
        call_id = context.metadata.get("call_id", "")
        return call_id if isinstance(call_id, str) else ""

    def _deny(self, context: FunctionInvocationContext, *, reason: str, rule_fired: List[str]) -> None:
        context.result = {
            "error": "toolgovern denied this tool call.",
            "tool": context.function.name,
            "reason": reason,
            "rule_fired": rule_fired,
        }
        raise MiddlewareTermination(f"toolgovern denied tool call '{context.function.name}': {reason}")

    async def process(
        self,
        context: FunctionInvocationContext,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        call_id = self._call_id(context)
        approval_response = context.metadata.get("approval_response")

        if (
            call_id
            and approval_response is not None
            and isinstance(approval_response, Content)
            and approval_response.type == "function_approval_response"
            and call_id in self._tracked
        ):
            tracked = self._tracked.pop(call_id)
            outcome = self._registry.resolve_pending(
                tracked.pending_id,
                ResolvePendingInput(
                    decision="allow" if approval_response.approved else "deny",
                ),
            )
            if outcome.status == "resolved" and outcome.final_decision == "allow":
                await call_next()
                return
            reason = (
                "human reviewer denied the request"
                if outcome.final_decision == "deny"
                else f"pending approval could not be resolved ({outcome.status})"
            )
            self._deny(context, reason=reason, rule_fired=["toolgovern-approval-denied"])
            return

        args = _current_arguments(context)
        rule_context = RuleContext(
            agent_id=self._policy.agent_id or "default-agent",
            session_id=self._policy.session_id or "default-session",
            coordinator_id=self._policy.coordinator_id,
            tool=context.function.name,
            args=args,
            scope=self._scope(),
        )
        result = classify(
            rule_context,
            ClassifyOptions(
                disabled_rules=self._disabled_rules,
                downgrade_to_approval=self._downgrade_to_approval,
            ),
        )
        decision = result.decision
        if len(result.fired_rules) == 0 and self._policy.default_decision != "allow":
            decision = self._policy.default_decision

        if decision == "allow":
            await call_next()
            return

        rule_ids = [r.rule_id for r in result.fired_rules] or ["policy-default-decision"]

        if decision == "deny":
            self._deny(context, reason="; ".join(r.reason for r in result.fired_rules) or "policy default", rule_fired=rule_ids)
            return

        # require-approval: register durably, then surface through Agent Framework's OWN
        # function_approval_request content -- not a separate side channel.
        pending_id = self._registry.register_pending(
            agent_id=rule_context.agent_id,
            session_id=rule_context.session_id,
            coordinator_id=rule_context.coordinator_id,
            tool=context.function.name,
            args=args,
            scope=self._scope(),
            fired_rules=result.fired_rules,
            disabled_rules=self._disabled_rules,
            downgrade_to_approval=self._downgrade_to_approval,
        )
        if call_id:
            self._tracked[call_id] = _TrackedApproval(pending_id=pending_id)

        function_call_content = Content.from_function_call(
            call_id=call_id or pending_id,
            name=context.function.name,
            arguments=args,
        )
        context.result = Content.from_function_approval_request(
            id=call_id or pending_id,
            function_call=function_call_content,
            additional_properties={
                "toolgovern_pending_id": pending_id,
                "toolgovern_rule_fired": rule_ids,
            },
        )
        raise MiddlewareTermination(
            f"toolgovern: tool call '{context.function.name}' requires approval ({', '.join(rule_ids)})",
            result=context.result,
        )
