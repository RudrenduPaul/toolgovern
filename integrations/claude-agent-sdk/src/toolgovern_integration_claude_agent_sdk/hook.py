"""``governed_pretooluse_hook()`` -- a toolgovern-backed ``PreToolUse`` hook for the Claude Agent
SDK (PyPI package ``claude-agent-sdk``).

Why this integration point, and why now: real market signal (2025-07 onward) shows
``claude-agent-sdk`` passing AutoGen in enterprise production-deployment count in early-to-mid
2026, and it shipped with zero toolgovern coverage until this package. Its ``PreToolUse`` hook is
also, mechanically, the cleanest governance seam toolgovern has adapted to yet: it fires before
*any* tool executes, is handed the exact tool name and input the model is about to invoke, and
returns a structured permission decision (allow / deny / ask / defer) the CLI enforces itself --
there is no wrapper-per-tool indirection to get right, no risk of a tool executing through some
path this package failed to wrap.

Verified against the real installed package (``pip install claude-agent-sdk``, version 0.2.122 at
the time this was written) by reading ``claude_agent_sdk/types.py`` directly rather than trusting a
docs summary:

* ``HookCallback = Callable[[HookInput, str | None, HookContext], Awaitable[HookJSONOutput]]`` --
  the callback the SDK calls is **async**, not sync. The common assumption that "PreToolUse is
  synchronous" is true from the *framework's* perspective -- the CLI blocks the tool call
  on this hook's result before letting it run -- but the Python callback itself is an
  ``async def``, which this module's own hook function is too.
* ``PreToolUseHookInput`` carries ``tool_name: str`` and ``tool_input: dict[str, Any]`` --
  precisely the ``(tool, args)`` shape ``toolgovern.classify()`` already evaluates; no adapter
  needed beyond reading those two keys off the input ``TypedDict``.
* The hook's return shape is a ``SyncHookJSONOutput`` dict with a
  ``hookSpecificOutput: PreToolUseHookSpecificOutput`` carrying
  ``permissionDecision: Literal["allow", "deny", "ask", "defer"]`` (plus an optional
  ``permissionDecisionReason``). This module only ever emits ``"allow"`` or ``"deny"`` --
  toolgovern's own decision space is exactly {allow, deny, require-approval}, and a
  require-approval that cannot be resolved synchronously fails closed to a real ``"deny"`` (see
  below), never a bare pass-through to the CLI's own ``"ask"`` UI. ``updatedInput`` (the SDK's
  documented "modify input before execution" capability) is not populated by this module --
  toolgovern's classifier is a pure gate, it does not rewrite arguments, so there is nothing
  genuine to put there yet.
* Hooks registered on the same event are dispatched **concurrently** by the CLI (see
  ``ClaudeAgentOptions.hooks``'s docstring) -- this hook has no shared mutable state across calls
  beyond what the caller explicitly passes in (a shared ``PendingApprovalRegistry``,
  ``TraceWriter``, or ``ScopeRegistry``, all already built to be safely shared: the registry is
  lock-guarded, the trace writer append-only).

Require-approval handling: a ``PreToolUse`` hook has no built-in notion of "pause and wait for a
human" the way a LangGraph interrupt does -- once this coroutine returns, the CLI acts on the
decision immediately. So a ``require-approval`` verdict is handled exactly like the durable
approval story the rest of toolgovern already ships (``packages/toolgovern/src/approval``, ported
at ``python/src/toolgovern/approval/pending_registry.py``): the decision is registered in a
``PendingApprovalRegistry`` first (via ``register_pending()``), *before* anything else is
attempted, so a durable, resolvable record exists no matter what happens next. Then, if the caller
supplied an ``on_approval_required`` async callable, this hook awaits it (bounded by
``approval_timeout_s``). If that handler genuinely answers in time, its answer is the final
decision, and the registry entry is closed out as resolved. If there is no handler, the handler
raises, or it does not answer before the timeout, this hook **fails closed**: the call is denied,
and the denial reason names the pending approval id so a human (or an out-of-band webhook/CLI/
review-queue process) can resolve it later via ``PendingApprovalRegistry.resolve_pending()`` /
``toolgovern.resume_pending_approval()`` -- exactly the flow the durable registry already supports
for every other framework this project has wired up.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping, Optional, Sequence, Union

from toolgovern import (
    AgentIdSource,
    ApprovalOutcome,
    ClassifyOptions,
    Decision,
    GateDecisionInfo,
    InvalidAgentIdError,
    PendingApprovalRegistry,
    Policy,
    ResolvePendingInput,
    RuleContext,
    RuleOverrides,
    ScopeDeclaration,
    ScopeRegistry,
    SpawnSubAgentParams,
    TraceEntryInput,
    TraceWriter,
    classify,
    is_valid_agent_id,
)

_DEFAULT_APPROVAL_TIMEOUT_S = 30.0

# A handler for require-approval decisions this hook cannot resolve any other way. Unlike
# govern_tool()'s synchronous, thread-based ApprovalHandler, this one is a native coroutine
# function -- the hook callback itself is already `async def` (see the module docstring's
# HookCallback finding), so there is no need to reach for a worker thread the way the
# synchronous govern_tool() path does; asyncio.wait_for() is the direct equivalent of that
# thread-join-with-timeout, in the concurrency model this callback already runs under.
ApprovalHandlerResult = Union[bool, ApprovalOutcome]
AsyncApprovalHandler = Callable[[GateDecisionInfo], Awaitable[ApprovalHandlerResult]]


class InvalidHookInputError(Exception):
    """Raised when the hook is invoked with a ``HookInput`` whose ``hook_event_name`` is not
    ``"PreToolUse"``. A ``HookMatcher`` registered under ``ClaudeAgentOptions.hooks["PreToolUse"]``
    will never deliver anything else, but this guards against the hook being mis-wired under a
    different event key, where blithely returning ``{}`` (a silent no-op) would hide the
    misconfiguration instead of surfacing it."""

    def __init__(self, hook_event_name: object) -> None:
        self.hook_event_name = hook_event_name
        super().__init__(
            "toolgovern's governed_pretooluse_hook() was invoked with "
            f"hook_event_name={hook_event_name!r}, not 'PreToolUse'. Register it only under "
            "ClaudeAgentOptions(hooks={'PreToolUse': [HookMatcher(hooks=[...])]})."
        )


@dataclass
class GovernedHookOptions:
    """Options for ``governed_pretooluse_hook()``. Deliberately the same shape as
    ``toolgovern.GovernToolOptions`` (the ``govern_tool()`` tool-wrapper's options) minus the
    fields that only make sense for a tool-wrapper (``idempotency``, ``on_tool_result`` -- this
    hook never itself calls the tool, so there is no result to see) plus the two fields a
    ``PreToolUse`` hook needs that a tool-wrapper does not (``on_approval_required`` as an async
    callable, and ``approval_timeout_s`` in seconds rather than milliseconds, matching asyncio's
    own convention).
    """

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
    on_approval_required: Optional[AsyncApprovalHandler] = None
    """Awaited only for require-approval decisions, bounded by ``approval_timeout_s``. Omitted
    entirely (the default) means every require-approval decision fails closed to deny -- there is
    no such thing as an implicit approval. May be a plain ``async def`` returning ``bool`` or
    ``ApprovalOutcome``; a synchronous callable returning either type also works (its return value
    is awaited only if it is itself awaitable), so a caller is not forced into ``async`` just to
    supply a handler that happens to decide synchronously."""
    approval_timeout_s: float = _DEFAULT_APPROVAL_TIMEOUT_S
    pending_approvals: Optional[PendingApprovalRegistry] = None
    """Durable registry for require-approval decisions -- see the module docstring. Strongly
    recommended whenever ``on_approval_required`` is omitted or may not answer in time, since it is
    the only way a fail-closed decision here can still be resolved later, out of band."""
    on_decision: Optional[Callable[[GateDecisionInfo], None]] = None
    """Fires after every gate decision (allow/deny alike), after the trace entry (if any) has been
    written -- same contract as ``GovernToolOptions.on_decision``."""

    @classmethod
    def from_policy(cls, policy: Policy, **overrides: Any) -> "GovernedHookOptions":
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


def _resolve_effective_scope(
    options: GovernedHookOptions, agent_id: str, session_id: str
) -> ScopeDeclaration:
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
    """Mirrors ``toolgovern``'s own (private) resolution-tracking shape for ``govern_tool()``:
    ``answered=True`` means the handler itself genuinely produced a result before the timeout --
    a real decision, allow or deny. ``answered=False`` covers every case where nothing genuine
    came back (no handler, a raising handler, a timeout) -- this hook still denies either way, but
    only a genuine answer closes out a ``pending_approvals`` registry entry as resolved; a
    fail-closed default leaves it 'pending' for a later out-of-band resolution."""

    outcome: ApprovalOutcome
    answered: bool


async def _resolve_approval(
    handler: Optional[AsyncApprovalHandler], info: GateDecisionInfo, timeout_s: float
) -> _ApprovalResolution:
    if not handler:
        return _ApprovalResolution(outcome=ApprovalOutcome(approved=False), answered=False)

    async def _run() -> ApprovalHandlerResult:
        result = handler(info)
        if hasattr(result, "__await__"):
            result = await result  # type: ignore[assignment]
        return result  # type: ignore[return-value]

    try:
        result = await asyncio.wait_for(_run(), timeout=timeout_s)
        return _ApprovalResolution(outcome=_normalize_approval_result(result), answered=True)
    except asyncio.TimeoutError:
        return _ApprovalResolution(outcome=ApprovalOutcome(approved=False), answered=False)
    except Exception:
        # A handler that raises must fail closed exactly like "no handler" or "timed out" -- it
        # must NOT propagate out of the hook, which would surface a raw, unrelated error to the
        # SDK's hook dispatcher instead of a clean deny decision.
        return _ApprovalResolution(outcome=ApprovalOutcome(approved=False), answered=False)


def _reason_for(fired_rules: Sequence[Any], decision: str) -> str:
    if fired_rules:
        parts = [f"{r.rule_id}: {r.reason}" for r in fired_rules]
        return "; ".join(parts)
    return f'toolgovern policy default decision "{decision}" (no rule fired).'


def _pretooluse_output(permission_decision: str, reason: Optional[str] = None) -> Mapping[str, Any]:
    hook_specific_output: dict = {
        "hookEventName": "PreToolUse",
        "permissionDecision": permission_decision,
    }
    if reason:
        hook_specific_output["permissionDecisionReason"] = reason
    return {"hookSpecificOutput": hook_specific_output}


def governed_pretooluse_hook(options: GovernedHookOptions) -> Callable[[Any, Optional[str], Any], Awaitable[Mapping[str, Any]]]:
    """Builds a ``PreToolUse`` ``HookCallback`` (see the module docstring for the exact signature
    this was verified against) that runs every tool call the SDK is about to make through
    toolgovern's classifier before it executes.

    Wire it up with::

        from claude_agent_sdk import ClaudeAgentOptions, HookMatcher
        from toolgovern_integration_claude_agent_sdk import GovernedHookOptions, governed_pretooluse_hook

        hook = governed_pretooluse_hook(GovernedHookOptions(scope=my_scope, agent_id="research-sub"))
        options = ClaudeAgentOptions(hooks={"PreToolUse": [HookMatcher(hooks=[hook])]})

    Raises ``toolgovern.InvalidAgentIdError`` at *build* time (not per-call) if
    ``options.agent_id`` is supplied but fails toolgovern's format check -- the same fail-fast
    behavior ``govern_tool()`` has.
    """
    if options.agent_id is not None and not is_valid_agent_id(options.agent_id):
        raise InvalidAgentIdError(options.agent_id)
    agent_id_source: AgentIdSource = "explicit" if options.agent_id is not None else "fallback"
    agent_id = options.agent_id if options.agent_id is not None else "default-agent"
    session_id = options.session_id if options.session_id is not None else "default-session"
    coordinator_id = options.coordinator_id
    disabled_rules = list(options.rules.disable) if options.rules else []
    downgrade_to_approval = list(options.rules.require_approval) if options.rules else []
    default_decision = options.default_decision or "allow"

    async def hook(input: Mapping[str, Any], tool_use_id: Optional[str], context: Any) -> Mapping[str, Any]:
        hook_event_name = input.get("hook_event_name")
        if hook_event_name != "PreToolUse":
            raise InvalidHookInputError(hook_event_name)

        tool_name: str = input["tool_name"]
        tool_input: Mapping[str, Any] = input.get("tool_input") or {}

        effective_scope = _resolve_effective_scope(options, agent_id, session_id)

        rule_context = RuleContext(
            agent_id=agent_id,
            session_id=session_id,
            coordinator_id=coordinator_id,
            tool=tool_name,
            args=tool_input,
            scope=effective_scope,
            scope_registry=options.scope_registry,
        )

        classifier_result = classify(
            rule_context,
            ClassifyOptions(disabled_rules=disabled_rules, downgrade_to_approval=downgrade_to_approval),
        )
        decision: str = classifier_result.decision
        fired_rules = classifier_result.fired_rules

        # A default_decision other than "allow" only applies when the classifier found nothing to
        # flag -- it never overrides an explicit rule verdict. Same contract as govern_tool().
        if len(fired_rules) == 0 and default_decision != "allow":
            decision = default_decision

        pending_id: Optional[str] = None
        if decision == "require-approval" and options.pending_approvals:
            pending_id = options.pending_approvals.register_pending(
                agent_id=agent_id,
                session_id=session_id,
                coordinator_id=coordinator_id,
                tool=tool_name,
                args=tool_input,
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
            tool=tool_name,
            args=tool_input,
            decision=decision,  # type: ignore[arg-type]
            fired_rules=fired_rules,
            scope=effective_scope,
            pending_id=pending_id,
        )

        final_decision = decision
        approved_by: Optional[str] = None
        reason = _reason_for(fired_rules, decision)

        if decision == "require-approval":
            resolution = await _resolve_approval(
                options.on_approval_required, info, options.approval_timeout_s
            )
            final_decision = "allow" if resolution.outcome.approved else "deny"
            approved_by = resolution.outcome.approved_by

            if pending_id and options.pending_approvals and resolution.answered:
                options.pending_approvals.resolve_pending(
                    pending_id,
                    ResolvePendingInput(decision=final_decision, approved_by=approved_by),
                )

            if resolution.answered:
                reason = (
                    f'require-approval resolved to "{final_decision}"'
                    + (f' by "{approved_by}"' if approved_by else "")
                    + f" ({_reason_for(fired_rules, decision)})."
                )
            elif pending_id:
                reason = (
                    f'toolgovern: tool "{tool_name}" requires human approval and no synchronous '
                    "resolution was available in this hook's execution context -- denied "
                    f"(fail-closed). Pending approval id: {pending_id!r}. Resolve it later via "
                    "PendingApprovalRegistry.resolve_pending() / "
                    "toolgovern.resume_pending_approval(). "
                    f"({_reason_for(fired_rules, decision)})"
                )
            else:
                reason = (
                    f'toolgovern: tool "{tool_name}" requires human approval; no '
                    "on_approval_required handler or pending_approvals registry was configured -- "
                    f"denied (fail-closed). ({_reason_for(fired_rules, decision)})"
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
                    session_id=session_id,
                    agent_id=agent_id,
                    tool=tool_name,
                    args=tool_input,
                    decision=final_decision,  # type: ignore[arg-type]
                    rule_fired=rule_fired_ids,
                    declared_scope=effective_scope,
                    approved_by=approved_by,
                    agent_id_source=agent_id_source,
                )
            )

        if options.on_decision:
            options.on_decision(info)

        if final_decision == "deny":
            return _pretooluse_output("deny", reason)
        return _pretooluse_output("allow")

    return hook
