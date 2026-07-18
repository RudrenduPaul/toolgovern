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

from ..approval.pending_registry import PendingApprovalRegistry, ResolvePendingInput
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
    pending_id: Optional[str] = None
    """The durable PendingApprovalRegistry id for this decision, when options.pending_approvals
    was supplied and this decision was require-approval. Lets an on_decision listener correlate
    the in-process (synchronous) outcome with the durable record a webhook/CLI/review queue can
    later resolve via resolve_pending(). Absent for every other decision, and absent entirely when
    no pending_approvals registry was configured."""


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
    pending_approvals: Optional[PendingApprovalRegistry] = None
    """Optional durable registry for require-approval decisions. When supplied, every
    require-approval decision is persisted here (via register_pending()) BEFORE
    on_approval_required (if any) is invoked -- so a caller who is not the in-process handler (a
    webhook, a CLI command, a human review queue) can resolve the same decision later via
    resolve_pending(), independent of this call's own synchronous window. Once the synchronous
    path genuinely answers (a real handler decision, not a fail-closed default), that outcome is
    reflected back into the registry so the entry reads 'resolved' and a later out-of-band
    resolve_pending() call correctly gets 'already-resolved' rather than re-deciding (or, for a
    side-effecting tool, re-executing) the same call twice. A fail-closed default (no handler, a
    timeout, or a throwing handler) deliberately does NOT close out the registry entry -- see
    execute()'s wiring below and resume_pending_approval(). Omitted entirely -- the default --
    leaves govern_tool()'s behavior completely unchanged."""
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


@dataclass(frozen=True)
class _ApprovalResolution:
    """What actually happened when govern_tool() tried to resolve a require-approval decision
    through the synchronous in-process path. ``answered=True`` means ``handler`` itself genuinely
    produced a result before the timeout -- a real decision, whether allow or deny. ``answered=
    False`` covers every case where nothing genuine came back: no handler was provided, the
    handler raised, or it simply didn't return before ``timeout_ms``. This distinction is what
    lets ``execute()`` decide whether a ``pending_approvals`` registry entry should be closed out
    as terminally resolved (a real decision was made) or left 'pending' for a later out-of-band
    resolve_pending()/resume_pending_approval() call to actually resolve. Either way, THIS
    execute() invocation still fails closed (denies) when answered is False, exactly as before
    this distinction existed -- only the registry's own bookkeeping changes."""

    outcome: ApprovalOutcome
    answered: bool


def _resolve_approval(
    handler: Optional[ApprovalHandler], info: GateDecisionInfo, timeout_ms: int
) -> _ApprovalResolution:
    if not handler:
        return _ApprovalResolution(outcome=ApprovalOutcome(approved=False), answered=False)

    # A handler that raises must fail closed exactly like "no handler" or "timed out" -- it
    # must NOT propagate out of govern_tool(), because that would skip the trace-append call
    # below and surface a raw, unrelated error instead of ToolGovernDenialError. An
    # unanswerable approval request is a denial, not an application crash.
    result_box: Dict[str, _ApprovalResolution] = {}

    def _run() -> None:
        try:
            result = handler(info)
            result_box["resolution"] = _ApprovalResolution(
                outcome=_normalize_approval_result(result), answered=True
            )
        except Exception:
            result_box["resolution"] = _ApprovalResolution(
                outcome=ApprovalOutcome(approved=False), answered=False
            )

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(timeout_ms / 1000)
    if thread.is_alive():
        # Timed out -- fail closed. The handler thread is left to finish in the background
        # (daemon=True), but its eventual result is discarded.
        return _ApprovalResolution(outcome=ApprovalOutcome(approved=False), answered=False)
    return result_box.get(
        "resolution", _ApprovalResolution(outcome=ApprovalOutcome(approved=False), answered=False)
    )


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

        # Registered BEFORE on_approval_required is invoked (or even looked at), so a durable
        # record of this decision exists regardless of whether the synchronous handler answers,
        # times out, raises, or was never provided at all -- see pending_approvals above.
        pending_id: Optional[str] = None
        if decision == "require-approval" and options.pending_approvals:
            pending_id = options.pending_approvals.register_pending(
                agent_id=agent_id,
                session_id=session_id,
                coordinator_id=coordinator_id,
                tool=tool.name,
                args=args,
                scope=effective_scope,
                fired_rules=fired_rules,
                agent_id_source=agent_id_source,
                disabled_rules=disabled_rules,
                downgrade_to_approval=downgrade_to_approval,
            )

        info = GateDecisionInfo(
            agent_id=agent_id,
            session_id=session_id,
            coordinator_id=coordinator_id,
            tool=tool.name,
            args=args,
            decision=decision,
            fired_rules=fired_rules,
            scope=effective_scope,
            pending_id=pending_id,
        )

        final_decision: Decision = decision
        approved_by: Optional[str] = None
        if decision == "require-approval":
            resolution = _resolve_approval(options.on_approval_required, info, approval_timeout_ms)
            final_decision = "allow" if resolution.outcome.approved else "deny"
            approved_by = resolution.outcome.approved_by

            # Only reflect this outcome back into the durable registry when the synchronous
            # handler actually, genuinely answered -- a real decision, allow or deny, is terminal:
            # a later resolve_pending()/resume_pending_approval() call must get
            # 'already-resolved', never a chance to re-decide or (for a side-effecting tool)
            # re-execute a call this process already finished with.
            #
            # When NOTHING genuinely answered (no handler, a raising handler, or a timeout), THIS
            # execute() call still fails closed exactly as before -- but the registry entry is
            # deliberately left 'pending', so the real approval can still arrive later, out of
            # band, via resolve_pending()/resume_pending_approval(). Reflecting a fail-closed
            # default back as if it were a real decision would make that async path permanently
            # unreachable.
            if pending_id and options.pending_approvals and resolution.answered:
                options.pending_approvals.resolve_pending(
                    pending_id,
                    ResolvePendingInput(decision=final_decision, approved_by=approved_by),
                )

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


class PendingApprovalNotResolvableError(Exception):
    """Raised by ``resume_pending_approval()`` when the ``pending_id`` it was given cannot be
    resolved to a fresh, actionable decision -- either because it (or its alias) is unrecognized,
    because it was already resolved by an earlier call (the synchronous path answering, or a
    previous resume), or because it expired. This is deliberately a different error from
    ``ToolGovernDenialError``: a denial is a real classifier/human verdict on the call; this is
    "there was nothing here left to resolve," which callers (a webhook handler, say) generally
    need to handle differently (e.g. respond 409/404 rather than "your request was denied")."""

    def __init__(self, pending_id: str, status: str) -> None:
        self.pending_id = pending_id
        self.status = status
        super().__init__(
            f"toolgovern: pending approval {pending_id!r} could not be resolved ({status})."
        )


@dataclass
class ResumePendingApprovalOptions:
    """Optional wiring resume_pending_approval() accepts -- deliberately the same shape of
    trace/on_decision/on_tool_result options govern_tool() itself accepts, so a caller resuming a
    pending approval gets the same trace/observability behavior as the original synchronous call
    would have."""

    trace: Optional[TraceWriter] = None
    on_decision: Optional[Callable[[GateDecisionInfo], None]] = None
    on_tool_result: Optional[Callable[[Any, RuleContext], Any]] = None


def resume_pending_approval(
    tool: ToolDefinition,
    registry: PendingApprovalRegistry,
    pending_id: str,
    resolution: ResolvePendingInput,
    options: Optional[ResumePendingApprovalOptions] = None,
) -> Any:
    """Closes the loop ``pending_approvals`` opens: given the SAME ``tool`` definition
    ``govern_tool()`` was originally wrapping, a ``PendingApprovalRegistry`` that call registered
    its require-approval decision in, the ``pending_id`` it was given back, and a resolution
    (allow/deny, optionally with ``edited_args``), this resolves the pending approval and -- if
    and only if the resolution (after any edited-args re-classification) comes back allow --
    actually invokes ``tool.execute()`` with the effective arguments, appends one trace entry with
    ``approved_by`` populated exactly as the synchronous path does, and returns the tool's result.

    This is the piece of the "durable, resumable approval" story that runs OUTSIDE the original
    ``govern_tool(...).execute()`` call -- from a webhook handler, a CLI command, or a long-running
    human review queue's worker loop, any time after that original call already returned (denied,
    most likely, if nothing answered its synchronous window). It does not, and cannot, resume that
    ORIGINAL execute() call itself -- that call already returned. What it does is perform the
    actual, real, gated execution the human's later decision authorizes, through the identical
    classify -> gate -> execute -> trace pipeline, so an edited/approved call still cannot skip
    re-classification and still produces a real audit trail.

    Raises ``PendingApprovalNotResolvableError`` if the pending approval is unrecognized, already
    resolved, or expired -- never silently does nothing. Raises ``ToolGovernDenialError`` if the
    resolution (or its edited-args re-classification) is a deny -- ``tool.execute()`` is never
    called in that case, exactly like a live ``govern_tool()`` denial.
    """
    options = options or ResumePendingApprovalOptions()
    pending = registry.get(pending_id)
    outcome = registry.resolve_pending(pending_id, resolution)

    if outcome.status != "resolved":
        raise PendingApprovalNotResolvableError(pending_id, outcome.status)

    effective_args = outcome.args if outcome.args is not None else (pending.args if pending else {})
    fired_rules = outcome.fired_rules if outcome.fired_rules is not None else (
        pending.fired_rules if pending else []
    )
    scope = pending.scope if pending else ScopeDeclaration()
    final_decision: Decision = "allow" if outcome.final_decision == "allow" else "deny"

    info = GateDecisionInfo(
        agent_id=pending.agent_id if pending else "default-agent",
        session_id=pending.session_id if pending else "default-session",
        coordinator_id=pending.coordinator_id if pending else None,
        tool=pending.tool if pending else tool.name,
        args=effective_args,
        decision=final_decision,
        fired_rules=fired_rules,
        scope=scope,
        pending_id=pending_id,
    )

    if options.trace:
        if fired_rules:
            rule_fired_ids = [r.rule_id for r in fired_rules]
        elif final_decision != "allow":
            rule_fired_ids = ["policy-default-decision"]
        else:
            rule_fired_ids = []
        options.trace.append(
            TraceEntryInput(
                session_id=info.session_id,
                agent_id=info.agent_id,
                tool=info.tool,
                args=effective_args,
                decision=final_decision,
                rule_fired=rule_fired_ids,
                declared_scope=scope,
                approved_by=outcome.approved_by,
                agent_id_source=pending.agent_id_source if pending else None,
            )
        )

    if options.on_decision:
        options.on_decision(info)

    if final_decision == "deny":
        raise ToolGovernDenialError(info)

    rule_context = RuleContext(
        agent_id=info.agent_id,
        session_id=info.session_id,
        coordinator_id=info.coordinator_id,
        tool=info.tool,
        args=effective_args,
        scope=scope,
    )

    try:
        result = tool.execute(effective_args)
        return options.on_tool_result(result, rule_context) if options.on_tool_result else result
    except Exception as error:
        if options.on_tool_result:
            return options.on_tool_result(error, rule_context)
        raise
