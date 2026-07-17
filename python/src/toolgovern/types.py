"""Shared types for the toolgovern middleware, classifier, scoping, and trace modules.

Ported from ``packages/toolgovern/src/types.ts``. A gate decision is always one of three
values -- there is no fourth "warn and continue" state, because a warning that does not
block execution is not governance, it is a log line.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Literal,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Union,
    runtime_checkable,
)

Decision = Literal["allow", "deny", "require-approval"]

# Where an ``agent_id`` came from when a gate decision was made: ``"explicit"`` means the
# caller passed ``agent_id=`` to ``govern_tool()`` directly; ``"fallback"`` means no agent_id
# was supplied and toolgovern used its default (``"default-agent"``). This is provenance, not
# proof -- toolgovern does not cryptographically verify that a caller actually is the agent it
# claims to be (see docs/security-model.md, "Agent identity is caller-asserted, not
# cryptographically verified").
AgentIdSource = Literal["explicit", "fallback"]

# The five v0.1 risk-rule categories. TG06/TG07 need cross-call session state and ship later.
RuleCategory = Literal["TG01", "TG02", "TG03", "TG04", "TG05"]

# A network scope value: False (no access), True (unrestricted), or an explicit hostname
# allowlist.
NetworkScope = Union[bool, Sequence[str]]


@dataclass(frozen=True)
class ScopeDeclaration:
    """A per-agent declared scope.

    ``network`` is either ``False`` (no network access at all), ``True`` (unrestricted --
    discouraged, but supported for local/dev use), or an explicit allowlist of hostnames.
    ``filesystem`` is a list of path prefixes the agent may read/write/delete under.
    ``credentials`` is a list of credential identifiers (file paths, secret names) the agent
    may access.
    """

    network: NetworkScope = False
    filesystem: Sequence[str] = field(default_factory=tuple)
    credentials: Sequence[str] = field(default_factory=tuple)


@dataclass(frozen=True)
class RuleOverrides:
    """Rule-level overrides a policy file can apply on top of the shipped rule pack defaults."""

    disable: Sequence[str] = field(default_factory=tuple)
    require_approval: Sequence[str] = field(default_factory=tuple)


@dataclass(frozen=True)
class Policy:
    """A loaded (or inline) policy.

    ``load_policy()`` returns this shape directly from a YAML file, and ``govern_tool()``
    accepts it as-is -- so a policy loaded from disk and an inline options object are the same
    type, which keeps the "wrap a tool" call site small.
    """

    scope: ScopeDeclaration
    policy: Optional[str] = None
    name: Optional[str] = None
    rules: Optional[RuleOverrides] = None
    default_decision: Decision = "allow"
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    coordinator_id: Optional[str] = None


@dataclass(frozen=True)
class AgentScopeRecord:
    """What the scoping registry recorded for one agent.

    The scope it requested at spawn time (only meaningful for sub-agents) and the scope
    actually granted after default-deny inheritance was applied against its coordinator's own
    scope.
    """

    agent_id: str
    session_id: str
    granted_scope: ScopeDeclaration
    coordinator_id: Optional[str] = None
    requested_scope: Optional[ScopeDeclaration] = None


@runtime_checkable
class ScopeRegistryReader(Protocol):
    """The minimal read surface TG05 needs from the scoping registry."""

    def get_record(self, agent_id: str) -> Optional[AgentScopeRecord]: ...


@dataclass(frozen=True)
class RuleContext:
    """The normalized input every classifier rule evaluates against."""

    agent_id: str
    session_id: str
    tool: str
    args: Mapping[str, Any]
    scope: ScopeDeclaration
    coordinator_id: Optional[str] = None
    # Present only when the caller wired a ScopeRegistry into classify(); used by TG05.
    scope_registry: Optional[ScopeRegistryReader] = None


@dataclass(frozen=True)
class RuleMatch:
    """A single fired rule's result. ``decision`` is never ``"allow"`` -- a rule either fires
    or it doesn't."""

    rule_id: str
    category: RuleCategory
    decision: Decision
    reason: str
    matched_argument: Optional[str] = None


@runtime_checkable
class Rule(Protocol):
    """A classifier rule: pure function from call context to an optional match."""

    id: str
    category: RuleCategory
    description: str

    def evaluate(self, ctx: RuleContext) -> Optional[RuleMatch]: ...


@dataclass(frozen=True)
class ClassifierResult:
    """The classifier's aggregate verdict for one tool call."""

    decision: Decision
    fired_rules: Sequence[RuleMatch]


@dataclass(frozen=True)
class TraceEntryInput:
    """What the caller supplies to ``TraceWriter.append()`` for one gate decision."""

    session_id: str
    agent_id: str
    tool: str
    args: Mapping[str, Any]
    decision: Decision
    rule_fired: Sequence[str]
    declared_scope: ScopeDeclaration
    approved_by: Optional[str] = None
    agent_id_source: Optional[AgentIdSource] = None


@dataclass(frozen=True)
class TraceEntry:
    """One append-only, signed trace record.

    ``signature`` is either ``sha256:<hex>`` (an unkeyed content hash of everything except
    ``signature`` itself -- the default) or ``hmac-sha256:<hex>`` (a keyed signature, when
    ``TraceWriter`` is given a ``secret_key``). ``prior_trace_id`` chains this entry to the one
    before it in the same session -- together these let a reader detect a missing, reordered,
    or tampered entry.
    """

    trace_id: str
    timestamp: str
    session_id: str
    agent_id: str
    tool: str
    arguments_hash: str
    decision: Decision
    rule_fired: Sequence[str]
    declared_scope: ScopeDeclaration
    signature: str
    prior_trace_id: Optional[str]
    agent_id_source: Optional[AgentIdSource] = None
    approved_by: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "tool": self.tool,
            "arguments_hash": self.arguments_hash,
            "decision": self.decision,
            "rule_fired": list(self.rule_fired),
            "declared_scope": {
                "network": self.declared_scope.network
                if isinstance(self.declared_scope.network, bool)
                else list(self.declared_scope.network),
                "filesystem": list(self.declared_scope.filesystem),
                "credentials": list(self.declared_scope.credentials),
            },
            "agent_id_source": self.agent_id_source,
            "signature": self.signature,
            "prior_trace_id": self.prior_trace_id,
            "approved_by": self.approved_by,
        }
