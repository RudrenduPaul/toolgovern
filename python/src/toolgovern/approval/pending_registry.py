"""``PendingApprovalRegistry`` -- a durable, keyed record of ``require-approval`` gate decisions
that outlives a single in-process, 30-second ``on_approval_required`` callback.

Ported from ``packages/toolgovern/src/approval/pending-registry.ts``. Python's ``govern_tool()``
is synchronous end-to-end (see ``middleware/on_tool_call.py``'s module docstring), so this port is
synchronous throughout too -- no ``asyncio`` was needed, matching the TS-vs-Python split already
established for ``classify()``/``classifyAsync()``.

Today's ``govern_tool()`` treats a ``require-approval`` decision as something that must be
answered synchronously, in-process, before its own ``execute()`` call returns. That is a real,
useful default, and this registry does not remove it -- it adds a second, independent path: every
``require-approval`` decision is also persisted here as a ``PendingApproval``, keyed by a
server-generated ``pending_id``, so a caller who is NOT the original in-process handler -- a
webhook receiving a Slack button click, a CLI command, a long-running human review queue polling
for pending items -- can look it up and resolve it later, on its own schedule, via
``resolve_pending()``.

Three design decisions here are load-bearing, each anchored to a real shipped bug or finding:

1. **``pending_id`` is always server-generated, never caller-supplied.** ``register_pending()``
   mints the ID and hands it back; there is no way to register (or resolve) a pending approval
   under an ID the caller chose. This directly closes the bypass Corridor's security bot found in
   langchain-ai/langgraph#8169's ``human_approval()`` helper: that implementation read its resume
   token (``resume_command_id``) out of the *untrusted resume payload* and, when the ID was
   unrecognized, silently created a brand-new pending decision for it instead of failing closed --
   so a caller who could resume an interrupted graph could mint a fresh ID and turn an
   expired/cancelled/mismatched approval into an approvable one. ``resolve_pending()`` below never
   creates an entry for an unrecognized ID; an unknown ``pending_id`` is ``"not-found"``, full
   stop.

2. **Alias tolerance for the same pending approval.** ``register_alias()`` lets a caller record
   that some other identifier (a rewritten thread ID, a provider-issued conversation ID) now also
   refers to an already-registered ``pending_id``; ``get()`` and ``resolve_pending()`` accept
   either the original ID or any registered alias. This models the fix in
   microsoft/agent-framework#6908 ("Python: Fix AG-UI approval thread aliases"): a stateful
   provider (Foundry) streamed back a new conversation ID mid-thread, and the approval had been
   registered only under the original client thread ID, so a client resuming with that original ID
   could never find its own pending approval.

3. **Edited arguments are re-classified, never smuggled through on the strength of the original
   approval.** ``resolve_pending()`` accepts ``edited_args``; when supplied alongside an
   ``"allow"`` decision, the edited arguments are run back through the classifier (the same
   ``classify()`` used by ``govern_tool()``, with the same rule overrides active at registration
   time) before the resolution is accepted. A re-classification that still comes back non-``allow``
   overrides the human's ``"allow"`` -- approving a call is not a license to edit its arguments
   into something riskier and have that edit wave through unchecked.

What this registry deliberately does NOT do: it does not itself execute a tool, and it does not
itself write to a ``TraceWriter``. It is a pure state machine over pending approvals.
``resume_pending_approval()`` in ``middleware/on_tool_call.py`` is the piece that actually closes
the loop.

This is also, by construction, in-memory only: a plain dict, scoped to one process. A production
deployment that needs the pending-approval record to survive a process restart, or to be resolved
from a different process than the one that registered it (the webhook case this whole feature is
aimed at), must back this with real durable storage behind the same interface -- that persistence
layer is out of scope for this pass.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Literal, Mapping, Optional, Sequence, Set

from ..classifier import ClassifyOptions, classify
from ..types import (
    AgentIdSource,
    ClassifierResult,
    Decision,
    RuleContext,
    RuleMatch,
    ScopeDeclaration,
)

# The two terminal decisions a pending approval can be resolved to. "require-approval" is never a
# valid resolution -- something either ends up allowed or denied.
ApprovalResolutionDecision = Literal["allow", "deny"]

PendingApprovalStatus = Literal["pending", "resolved", "expired"]
ResolvePendingStatus = Literal["resolved", "not-found", "already-resolved", "expired"]


@dataclass(frozen=True)
class PendingApprovalResolution:
    """What a resolved pending approval recorded about its own resolution."""

    decision: ApprovalResolutionDecision
    resolved_at: float
    approved_by: Optional[str] = None
    edited_args: Optional[Mapping[str, Any]] = None
    # Present only when edited_args was supplied and actually re-classified.
    reclassified: Optional[ClassifierResult] = None


@dataclass(frozen=True)
class PendingApproval:
    """The public, read-only view of one registered pending approval, as returned by ``get()``."""

    pending_id: str
    agent_id: str
    session_id: str
    tool: str
    args: Mapping[str, Any]
    scope: ScopeDeclaration
    fired_rules: Sequence[RuleMatch]
    status: PendingApprovalStatus
    created_at: float
    aliases: Sequence[str]
    coordinator_id: Optional[str] = None
    agent_id_source: Optional[AgentIdSource] = None
    expires_at: Optional[float] = None
    resolution: Optional[PendingApprovalResolution] = None


@dataclass(frozen=True)
class ResolvePendingInput:
    decision: ApprovalResolutionDecision
    approved_by: Optional[str] = None
    # Edited arguments to approve/deny instead of the originally registered args. When present
    # together with decision="allow", the edited arguments are re-run through the classifier
    # before the resolution is accepted -- see the module docstring, point 3.
    edited_args: Optional[Mapping[str, Any]] = None


@dataclass(frozen=True)
class ResolvePendingOutcome:
    status: ResolvePendingStatus
    # Echoes back whatever ID/alias the caller resolved with -- NOT necessarily the canonical
    # pending_id, when status is "not-found".
    pending_id: str
    final_decision: Optional[ApprovalResolutionDecision] = None
    approved_by: Optional[str] = None
    args: Optional[Mapping[str, Any]] = None
    fired_rules: Optional[Sequence[RuleMatch]] = None


class UnknownPendingApprovalError(Exception):
    """Raised by ``register_alias()`` when asked to alias an ID/alias with no registered entry.
    An alias must always point at a real, already-registered pending approval -- silently
    accepting one for an unknown ID would let a caller plant a phantom entry that later resolves
    as if it had gone through the classifier, which it never did."""

    def __init__(self, pending_id: str) -> None:
        self.pending_id = pending_id
        super().__init__(f"toolgovern: no pending approval is registered under id/alias {pending_id!r}.")


class PendingApprovalAliasConflictError(Exception):
    """Raised by ``register_alias()`` when ``alias`` already refers to a *different* pending
    approval than the one being aliased -- silently repointing it would let a second, unrelated
    call's resolution land on the first call's entry."""

    def __init__(self, alias: str) -> None:
        self.alias = alias
        super().__init__(f"toolgovern: alias {alias!r} already refers to a different pending approval.")


@dataclass
class _PendingApprovalEntry:
    pending_id: str
    agent_id: str
    session_id: str
    tool: str
    args: Mapping[str, Any]
    scope: ScopeDeclaration
    fired_rules: Sequence[RuleMatch]
    disabled_rules: Sequence[str]
    downgrade_to_approval: Sequence[str]
    created_at: float
    coordinator_id: Optional[str] = None
    agent_id_source: Optional[AgentIdSource] = None
    expires_at: Optional[float] = None
    aliases: Set[str] = field(default_factory=set)
    status: PendingApprovalStatus = "pending"
    resolution: Optional[PendingApprovalResolution] = None


class PendingApprovalRegistry:
    """A keyed, in-memory registry of pending ``require-approval`` gate decisions. See the module
    docstring above for the three bug-shaped design decisions this embodies.

    Thread-safe: a single lock guards every read/write, since Python's ``govern_tool()`` uses a
    worker thread for its own approval-timeout handling and a durable registry shared across
    threads (a web server's request-handling threads, say) must not race on registration or
    resolution.
    """

    def __init__(
        self,
        now: Optional[Callable[[], float]] = None,
        id_factory: Optional[Callable[[], str]] = None,
        reclassify: Optional[Callable[[RuleContext, ClassifyOptions], ClassifierResult]] = None,
    ) -> None:
        self._entries: Dict[str, _PendingApprovalEntry] = {}
        # alias -> canonical pending_id. A canonical pending_id is never itself a key in this map
        # -- _resolve_canonical_id() checks _entries first, so a real ID always wins over any alias.
        self._alias_to_canonical: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._now = now or (lambda: time.time() * 1000)
        self._id_factory = id_factory or (lambda: str(uuid.uuid4()))
        self._reclassify = reclassify or classify

    def register_pending(
        self,
        *,
        agent_id: str,
        session_id: str,
        tool: str,
        args: Mapping[str, Any],
        scope: ScopeDeclaration,
        fired_rules: Sequence[RuleMatch],
        coordinator_id: Optional[str] = None,
        agent_id_source: Optional[AgentIdSource] = None,
        disabled_rules: Optional[Sequence[str]] = None,
        downgrade_to_approval: Optional[Sequence[str]] = None,
        ttl_ms: Optional[int] = None,
    ) -> str:
        """Persists one ``require-approval`` gate decision and returns its server-generated
        ``pending_id``. The caller never supplies (and cannot influence) this ID -- see the
        module docstring, point 1."""
        with self._lock:
            pending_id = self._id_factory()
            created_at = self._now()
            entry = _PendingApprovalEntry(
                pending_id=pending_id,
                agent_id=agent_id,
                session_id=session_id,
                tool=tool,
                args=args,
                scope=scope,
                fired_rules=list(fired_rules),
                disabled_rules=list(disabled_rules) if disabled_rules else [],
                downgrade_to_approval=list(downgrade_to_approval) if downgrade_to_approval else [],
                created_at=created_at,
                coordinator_id=coordinator_id,
                agent_id_source=agent_id_source,
                expires_at=(created_at + ttl_ms) if ttl_ms is not None else None,
            )
            self._entries[pending_id] = entry
            return pending_id

    def register_alias(self, pending_id: str, alias: str) -> None:
        """Records that ``alias`` now also refers to the pending approval registered under
        ``pending_id`` (which may itself already be an alias). Resolving by ``pending_id`` OR
        ``alias`` afterward reaches the same entry. See the module docstring, point 2
        (microsoft/agent-framework#6908's thread-id-rewrite bug)."""
        with self._lock:
            canonical = self._resolve_canonical_id(pending_id)
            if canonical is None:
                raise UnknownPendingApprovalError(pending_id)
            existing_target = self._resolve_canonical_id(alias)
            if existing_target is not None and existing_target != canonical:
                raise PendingApprovalAliasConflictError(alias)
            self._entries[canonical].aliases.add(alias)
            self._alias_to_canonical[alias] = canonical

    def get(self, pending_id_or_alias: str) -> Optional[PendingApproval]:
        """Looks up a pending approval by its ``pending_id`` OR any registered alias. Returns
        ``None`` for anything unrecognized -- never fabricates an entry."""
        with self._lock:
            canonical = self._resolve_canonical_id(pending_id_or_alias)
            if canonical is None:
                return None
            return self._to_public(self._entries[canonical])

    def resolve_pending(
        self, pending_id_or_alias: str, resolution: ResolvePendingInput
    ) -> ResolvePendingOutcome:
        """Resolves a pending approval, by ``pending_id`` or any registered alias, to a terminal
        decision.

        - An unrecognized ``pending_id_or_alias`` returns ``status="not-found"`` -- it is NEVER
          treated as a fresh grant to be created on the spot. See the module docstring, point 1
          (langchain-ai/langgraph#8169's resume-token bypass).
        - An already-resolved entry returns ``status="already-resolved"`` with the *original*
          resolution's outcome -- resolving twice can never flip a decision or re-trigger
          execution.
        - An expired entry (past ``ttl_ms``) returns ``status="expired"`` and is marked
          ``"expired"``, never resolvable afterward.
        - Otherwise, the entry is resolved. If ``edited_args`` is supplied together with
          ``decision="allow"``, the edited arguments are re-run through the classifier (the same
          rule overrides captured at registration time); any result other than ``"allow"``
          overrides the human's ``"allow"`` down to ``"deny"``.
        """
        with self._lock:
            canonical = self._resolve_canonical_id(pending_id_or_alias)
            if canonical is None:
                return ResolvePendingOutcome(status="not-found", pending_id=pending_id_or_alias)

            entry = self._entries[canonical]

            if entry.status == "expired" or (
                entry.expires_at is not None and self._now() > entry.expires_at
            ):
                entry.status = "expired"
                return ResolvePendingOutcome(status="expired", pending_id=canonical)

            if entry.status == "resolved":
                prior = entry.resolution
                assert prior is not None
                return ResolvePendingOutcome(
                    status="already-resolved",
                    pending_id=canonical,
                    final_decision=prior.decision,
                    approved_by=prior.approved_by,
                    args=prior.edited_args if prior.edited_args is not None else entry.args,
                    fired_rules=prior.reclassified.fired_rules if prior.reclassified else None,
                )

            effective_args = resolution.edited_args if resolution.edited_args is not None else entry.args
            final_decision: ApprovalResolutionDecision = resolution.decision
            reclassified: Optional[ClassifierResult] = None

            if resolution.edited_args is not None and resolution.decision == "allow":
                # Approving an edit is never itself a bypass -- the edited arguments must clear
                # the same classifier a fresh call would. Anything other than a clean "allow" here
                # (including a fresh "require-approval", which this single resolve step cannot
                # itself re-adjudicate) overrides the human's decision down to "deny", fail-closed.
                ctx = RuleContext(
                    agent_id=entry.agent_id,
                    session_id=entry.session_id,
                    coordinator_id=entry.coordinator_id,
                    tool=entry.tool,
                    args=resolution.edited_args,
                    scope=entry.scope,
                )
                reclassified = self._reclassify(
                    ctx,
                    ClassifyOptions(
                        disabled_rules=entry.disabled_rules,
                        downgrade_to_approval=entry.downgrade_to_approval,
                    ),
                )
                if reclassified.decision != "allow":
                    final_decision = "deny"

            entry.status = "resolved"
            entry.resolution = PendingApprovalResolution(
                decision=final_decision,
                approved_by=resolution.approved_by,
                resolved_at=self._now(),
                edited_args=resolution.edited_args,
                reclassified=reclassified,
            )

            return ResolvePendingOutcome(
                status="resolved",
                pending_id=canonical,
                final_decision=final_decision,
                approved_by=resolution.approved_by,
                args=effective_args,
                fired_rules=reclassified.fired_rules if reclassified else None,
            )

    def _resolve_canonical_id(self, id_or_alias: str) -> Optional[str]:
        if id_or_alias in self._entries:
            return id_or_alias
        return self._alias_to_canonical.get(id_or_alias)

    def _to_public(self, entry: _PendingApprovalEntry) -> PendingApproval:
        return PendingApproval(
            pending_id=entry.pending_id,
            agent_id=entry.agent_id,
            session_id=entry.session_id,
            tool=entry.tool,
            args=entry.args,
            scope=entry.scope,
            fired_rules=list(entry.fired_rules),
            status=entry.status,
            created_at=entry.created_at,
            aliases=list(entry.aliases),
            coordinator_id=entry.coordinator_id,
            agent_id_source=entry.agent_id_source,
            expires_at=entry.expires_at,
            resolution=entry.resolution,
        )
