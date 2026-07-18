"""toolgovern -- runtime governance middleware for AI agent tool calls.

A gated call never reaches the wrapped tool's real implementation until the classifier returns
``allow``. Every decision is traceable to a specific rule ID; there is no unexplained black-box
denial. ``govern_tool()`` evaluating a call as ``allow`` means the call was checked against the
current rule set -- it is not a guarantee the call is safe.

This is a genuine Python port of the ``toolgovern`` npm package
(https://github.com/RudrenduPaul/toolgovern), not a wrapper around the Node binary. It ships the
same 35-rule classifier (TG01-TG05), the same default-deny scope-inheritance model, and the same
signed local audit trail (unkeyed sha256 by default, optional hmac-sha256 keyed signing).

One deliberate divergence from the TS original: TG03's DNS-resolution check
(``TG03-dns-resolves-private``) runs as an ordinary synchronous member of the one ``classify()``
rule registry here, because ``govern_tool()`` is synchronous end-to-end in this port and
``socket.getaddrinfo()`` is itself a blocking call -- no separate async entry point was needed.
The TS package instead keeps this specific rule in a separate ``classifyAsync()``-only registry,
since Node's DNS resolution is Promise-based and the TS rule registry stays at its pre-existing
34-rule count for that reason. Same check, same failure-closed behavior, different plumbing
dictated by each language's own concurrency model -- see ``docs/security-model.md`` for the full
writeup.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .approval import (
    ApprovalResolutionDecision,
    PendingApproval,
    PendingApprovalAliasConflictError,
    PendingApprovalRegistry,
    PendingApprovalResolution,
    PendingApprovalStatus,
    ResolvePendingInput,
    ResolvePendingOutcome,
    ResolvePendingStatus,
    UnknownPendingApprovalError,
)
from .classifier import (
    ClassifyOptions,
    classify,
    credential_access_rules,
    cross_agent_inheritance_rules,
    filesystem_scope_rules,
    network_egress_rules,
    rule_registry,
    shell_risk_rules,
)
from .mcp_trust import (
    Algorithm as McpTrustAlgorithm,
    DEFAULT_MANIFEST_FETCH_TIMEOUT_SECONDS,
    FetchImpl as McpManifestFetchImpl,
    McpManifestEnvelope,
    McpServerConnectionRequest,
    McpTrustDecision,
    McpTrustPolicy,
    McpTrustVerdict,
    PinnedPublicKey,
    assert_mcp_server_trusted,
    is_origin_allowed,
    verify_mcp_server_manifest,
)
from .middleware import (
    ApprovalHandler,
    ApprovalOutcome,
    GateDecisionInfo,
    GovernToolOptions,
    IdempotencyCache,
    IdempotencyOptions,
    InvalidAgentIdError,
    PendingApprovalNotResolvableError,
    ResumePendingApprovalOptions,
    ToolDefinition,
    ToolGovernDenialError,
    govern_tool,
    resume_pending_approval,
)
from .policy import PolicyValidationError, PolicyValidationResult, as_policy, load_policy, validate_policy
from .scoping import (
    EMPTY_SCOPE,
    ScopeRegistry,
    SpawnSubAgentParams,
    compute_inherited_scope,
    has_zero_capability,
    is_valid_agent_id,
    is_valid_scope_declaration,
    normalize_scope,
)
from .trace import (
    ChainVerificationIssue,
    ChainVerificationResult,
    TraceQuery,
    TraceWriter,
    TraceWriterOptions,
    VerifyChainOptions,
    canonical_json,
    compute_entry_content_hash,
    compute_entry_signature,
    filter_trace,
    parse_since,
    read_trace,
    verify_chain,
)
from .types import (
    AgentIdSource,
    AgentScopeRecord,
    ClassifierResult,
    Decision,
    Policy,
    Rule,
    RuleCategory,
    RuleContext,
    RuleMatch,
    RuleOverrides,
    ScopeDeclaration,
    ScopeRegistryReader,
    TraceEntry,
    TraceEntryInput,
)

__all__ = [
    "__version__",
    # types
    "AgentIdSource",
    "AgentScopeRecord",
    "ClassifierResult",
    "Decision",
    "Policy",
    "Rule",
    "RuleCategory",
    "RuleContext",
    "RuleMatch",
    "RuleOverrides",
    "ScopeDeclaration",
    "ScopeRegistryReader",
    "TraceEntry",
    "TraceEntryInput",
    # mcp_trust
    "McpTrustAlgorithm",
    "DEFAULT_MANIFEST_FETCH_TIMEOUT_SECONDS",
    "McpManifestFetchImpl",
    "McpManifestEnvelope",
    "McpServerConnectionRequest",
    "McpTrustDecision",
    "McpTrustPolicy",
    "McpTrustVerdict",
    "PinnedPublicKey",
    "assert_mcp_server_trusted",
    "is_origin_allowed",
    "verify_mcp_server_manifest",
    # middleware
    "ApprovalHandler",
    "ApprovalOutcome",
    "GateDecisionInfo",
    "GovernToolOptions",
    "IdempotencyCache",
    "IdempotencyOptions",
    "InvalidAgentIdError",
    "PendingApprovalNotResolvableError",
    "ResumePendingApprovalOptions",
    "ToolDefinition",
    "ToolGovernDenialError",
    "govern_tool",
    "resume_pending_approval",
    # approval
    "ApprovalResolutionDecision",
    "PendingApproval",
    "PendingApprovalAliasConflictError",
    "PendingApprovalRegistry",
    "PendingApprovalResolution",
    "PendingApprovalStatus",
    "ResolvePendingInput",
    "ResolvePendingOutcome",
    "ResolvePendingStatus",
    "UnknownPendingApprovalError",
    # classifier
    "ClassifyOptions",
    "classify",
    "rule_registry",
    "shell_risk_rules",
    "filesystem_scope_rules",
    "network_egress_rules",
    "credential_access_rules",
    "cross_agent_inheritance_rules",
    # scoping
    "EMPTY_SCOPE",
    "ScopeRegistry",
    "SpawnSubAgentParams",
    "compute_inherited_scope",
    "has_zero_capability",
    "is_valid_agent_id",
    "is_valid_scope_declaration",
    "normalize_scope",
    # trace
    "TraceWriter",
    "TraceWriterOptions",
    "compute_entry_content_hash",
    "compute_entry_signature",
    "read_trace",
    "filter_trace",
    "parse_since",
    "verify_chain",
    "TraceQuery",
    "ChainVerificationResult",
    "ChainVerificationIssue",
    "VerifyChainOptions",
    "canonical_json",
    # policy
    "load_policy",
    "PolicyValidationError",
    "validate_policy",
    "as_policy",
    "PolicyValidationResult",
]
