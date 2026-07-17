"""``govern_tool()`` -- the core hook.

Ported from ``packages/toolgovern/src/middleware/onToolCall.ts``.

Wraps any tool definition a framework already has and returns a version that evaluates every
invocation through the classifier before the underlying tool executes. No framework fork
required: this is designed to slot into a single call site (e.g. a tool-executor wrapper) with
one wrapping call.

A gated call never reaches the real tool implementation until the classifier's decision resolves
to ``allow``. ``deny`` raises ``ToolGovernDenialError`` without executing the tool at all.
``require-approval`` calls ``on_approval_required`` if one was provided; with no handler, or if
the handler times out, the call fails closed (denied) -- an unanswered approval request is never
treated as a yes.

This Python port is synchronous (matching ``load_policy()``'s "runs once, no event loop
required" design and the rest of this package), unlike the TS original's async/await
middleware -- the classifier itself is pure and synchronous in both languages; only the I/O
around it (trace writes, an approval handler) differs. Approval timeouts are implemented with a
worker thread joined with a timeout, the synchronous equivalent of ``Promise.race`` against a
``setTimeout``.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Union

from ..classifier import ClassifyOptions, classify
from ..scoping.inheritance_enforcer import ScopeRegistry, SpawnSubAgentParams
from ..scoping.scope_declaration import is_valid_agent_id
from ..trace.trace_writer import TraceWriter
from ..types import (
    AgentIdSource,
    Decision,
    Policy,
    RuleContext,
    RuleMatch,
    RuleOverrides,
    ScopeDeclaration,
    TraceEntryInput,
)
from .idempotency_cache import IdempotencyCache, IdempotencyOptions

_DEFAULT_APPROVAL_TIMEOUT_MS = 30_000


@dataclass(frozen=True)
class ToolDefinition:
    """A gateable tool: a name and a callable that executes it. ``execute`` takes the call's
    ``args`` mapping and returns (or raises) a result."""

    name: str
    execute: Callable[[Mapping[str, Any]], Any]


@dataclass(frozen=True)
class GateDecisionInfo:
    """Everything surfaced to ``on_approval_required`` and ``on_decision`` about one gate
    decision."""

    agent_id: str
    session_id: str
    tool: str
    args: Mapping[str, Any]
    decision: Decision
    fired_rules: Sequence[RuleMatch]
    scope: ScopeDeclaration
    coordinator_id: Optional[str] = None


@dataclass(frozen=True)
class ApprovalOutcome:
    """What an ``ApprovalHandler`` resolves to when it wants to record who made the call, not
    just whether it was approved. A handler may still just return a plain bool --
    ``approved_by`` is optional identity metadata, never required to resolve an approval."""

    approved: bool
    approved_by: Optional[str] = None


# A handler may return a bool or an ApprovalOutcome.
ApprovalHandlerResult = Union[bool, ApprovalOutcome]
ApprovalHandler = Callable[[GateDecisionInfo], ApprovalHandlerResult]


class ToolGovernDenialError(Exception):
    def __init__(self, decision_info: GateDecisionInfo) -> None:
        self.decision_info = decision_info
        rule_ids = ", ".join(r.rule_id for r in decision_info.fired_rules) or "policy default"
        super().__init__(
            f'toolgovern denied tool call "{decision_info.tool}" '
            f'(agent "{decision_info.agent_id}"): {rule_ids}'
        )


class InvalidAgentIdError(Exception):
    """Raised by ``govern_tool()`` when an explicitly-supplied ``agent_id`` fails the format
    check in ``is_valid_agent_id()`` (empty, excessively long, or containing
    control/injection-style characters). This is a format rejection, not an
    identity-verification failure -- toolgovern cannot tell a malformed agent_id apart from a
    well-formed one that is still a lie; it can only refuse to treat obviously-malformed input
    as an identity at all. See docs/security-model.md, "Agent identity is caller-asserted, not
    cryptographically verified."
    """

    def __init__(self, raw_agent_id: str) -> None:
        self.raw_agent_id = raw_agent_id
        super().__init__(
            f"toolgovern rejected a malformed agent_id: {raw_agent_id!r}. It must be a "
            "non-empty string, no longer than 256 characters, with no control characters. "
            "This is a format check only -- it does not verify the caller actually is the "
            "agent it claims to be."
        )


@dataclass
class GovernToolOptions:
    """``options`` is a ``Policy`` (whether hand-written inline or returned by
    ``load_policy()``) plus optional runtime wiring (``scope_registry``, ``trace``, approval
    handling)."""

    scope: ScopeDeclaration
    policy: Optional[str] = None
    name: Optional[str] = None
    rules: Optional[RuleOverrides] = None
    default_decision: Decision = "allow"
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    coordinator_id: Optional[str] = None

    scope_registry: Optional[ScopeRegistry] = None
    trace: Optional[TraceWriter] = None
    on_approval_required: Optional[ApprovalHandler] = None
    """Called only for require-approval decisions. Return True to allow the call through,
    False to deny it -- or an ApprovalOutcome to also record who decided. Omitted entirely
    means every require-approval decision is denied (fail-closed) -- there is no such thing as
    an implicit approval."""
    approval_timeout_ms: int = _DEFAULT_APPROVAL_TIMEOUT_MS
    on_decision: Optional[Callable[[GateDecisionInfo], None]] = None
    """Fires after every gate decision, allow/deny/require-approval alike, after the trace
    entry (if any) has been written."""
    on_tool_result: Optional[Callable[[Any, RuleContext], Any]] = None
    """Optional post-execution hook. Once a call is allowed and tool.execute() has run (or
    raised), the raw result -- or the raised exception, if execute() raised -- is passed
    through this function before anything is returned to the caller."""
    idempotency: Optional[IdempotencyOptions] = None

    @classmethod
    def from_policy(cls, policy: Policy, **overrides: Any) -> "GovernToolOptions":
        return cls(
            scope=policy.scope,
            policy=policy.policy,
            name=policy.name,
            rules=policy.rules,
            default_decision=policy.default_decision,
            agent_id=policy.agent_id,
            session_id=policy.session_id,
            coordinator_id=policy.coordinator_id,
            **overrides,
        )


def _resolve_effective_scope(options: GovernToolOptions, agent_id: str, session_id: str) -> ScopeDeclaration:
    if not options.scope_registry:
        return options.scope

    existing = options.scope_registry.get_record(agent_id)
    if existing:
        return existing.granted_scope

    if options.coordinator_id:
        return options.scope_registry.spawn_sub_agent(
            SpawnSubAgentParams(
                coordinator_id=options.coordinator_id,
                sub_agent_id=agent_id,
                session_id=session_id,
                requested_scope=options.scope,
            )
        ).granted_scope
    return options.scope_registry.register_root_agent(agent_id, session_id, options.scope).granted_scope


def _normalize_approval_result(result: ApprovalHandlerResult) -> ApprovalOutcome:
    if isinstance(result, bool):
        return ApprovalOutcome(approved=result)
    return result


def _resolve_approval(
    handler: Optional[ApprovalHandler], info: GateDecisionInfo, timeout_ms: int
) -> ApprovalOutcome:
    if not handler:
        return ApprovalOutcome(approved=False)

    # A handler that raises must fail closed exactly like "no handler" or "timed out" -- it
    # must NOT propagate out of govern_tool(), because that would skip the trace-append call
    # below and surface a raw, unrelated error instead of ToolGovernDenialError. An
    # unanswerable approval request is a denial, not an application crash.
    outcome_box: Dict[str, ApprovalOutcome] = {}

    def _run() -> None:
        try:
            result = handler(info)
            outcome_box["outcome"] = _normalize_approval_result(result)
        except Exception:
            outcome_box["outcome"] = ApprovalOutcome(approved=False)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(timeout_ms / 1000)
    if thread.is_alive():
        # Timed out -- fail closed. The handler thread is left to finish in the background
        # (daemon=True), but its eventual result is discarded.
        return ApprovalOutcome(approved=False)
    return outcome_box.get("outcome", ApprovalOutcome(approved=False))


def govern_tool(tool: ToolDefinition, options: GovernToolOptions) -> ToolDefinition:
    """Wraps ``tool`` so every call is evaluated by the classifier before it executes."""
    # agent_id is a caller-asserted string, never cryptographically verified (see
    # docs/security-model.md). What we CAN do here is reject a malformed one outright, and
    # record whether this call's agent_id was explicitly supplied or fell back to the default.
    if options.agent_id is not None and not is_valid_agent_id(options.agent_id):
        raise InvalidAgentIdError(options.agent_id)
    agent_id_source: AgentIdSource = "explicit" if options.agent_id is not None else "fallback"
    agent_id = options.agent_id if options.agent_id is not None else "default-agent"
    session_id = options.session_id if options.session_id is not None else "default-session"
    coordinator_id = options.coordinator_id
    disabled_rules = list(options.rules.disable) if options.rules else []
    downgrade_to_approval = list(options.rules.require_approval) if options.rules else []
    default_decision = options.default_decision or "allow"
    approval_timeout_ms = options.approval_timeout_ms
    # Scoped to this one gated tool instance -- never shared globally across every gate in a
    # process.
    idempotency_cache: Optional[IdempotencyCache] = (
        IdempotencyCache(options.idempotency.ttl_ms) if options.idempotency and options.idempotency.enabled else None
    )

    def execute(args: Mapping[str, Any]) -> Any:
        effective_scope = _resolve_effective_scope(options, agent_id, session_id)

        rule_context = RuleContext(
            agent_id=agent_id,
            session_id=session_id,
            coordinator_id=coordinator_id,
            tool=tool.name,
            args=args,
            scope=effective_scope,
            scope_registry=options.scope_registry,
        )

        classifier_result = classify(
            rule_context,
            ClassifyOptions(disabled_rules=disabled_rules, downgrade_to_approval=downgrade_to_approval),
        )
        decision: Decision = classifier_result.decision
        fired_rules = classifier_result.fired_rules

        # A default_decision other than "allow" only applies when the classifier found nothing
        # to flag -- it never overrides an explicit rule verdict.
        if len(fired_rules) == 0 and default_decision != "allow":
            decision = default_decision

        info = GateDecisionInfo(
            agent_id=agent_id,
            session_id=session_id,
            coordinator_id=coordinator_id,
            tool=tool.name,
            args=args,
            decision=decision,
            fired_rules=fired_rules,
            scope=effective_scope,
        )

        final_decision: Decision = decision
        approved_by: Optional[str] = None
        if decision == "require-approval":
            outcome = _resolve_approval(options.on_approval_required, info, approval_timeout_ms)
            final_decision = "allow" if outcome.approved else "deny"
            approved_by = outcome.approved_by

        if options.trace:
            if fired_rules:
                rule_fired_ids = [r.rule_id for r in fired_rules]
            elif decision != "allow":
                rule_fired_ids = ["policy-default-decision"]
            else:
                rule_fired_ids = []

            options.trace.append(
                TraceEntryInput(
                    session_id=session_id,
                    agent_id=agent_id,
                    tool=tool.name,
                    args=args,
                    decision=final_decision,
                    rule_fired=rule_fired_ids,
                    declared_scope=effective_scope,
                    approved_by=approved_by,
                    agent_id_source=agent_id_source,
                )
            )

        if options.on_decision:
            options.on_decision(info)

        if final_decision == "deny":
            raise ToolGovernDenialError(info)

        # A raised execute() (whether run directly or via the idempotency cache below) is
        # caught here rather than left to propagate directly, so on_tool_result (when
        # provided) gets a chance to see it before anything reaches the caller. With no
        # on_tool_result, behavior is unchanged: a caught error is simply re-raised.
        try:
            if idempotency_cache:
                result = idempotency_cache.claim_if_absent(
                    IdempotencyCache.key_for(tool.name, args), lambda: tool.execute(args)
                )
            else:
                result = tool.execute(args)
            return options.on_tool_result(result, rule_context) if options.on_tool_result else result
        except Exception as error:
            if options.on_tool_result:
                return options.on_tool_result(error, rule_context)
            raise

    return ToolDefinition(name=tool.name, execute=execute)
