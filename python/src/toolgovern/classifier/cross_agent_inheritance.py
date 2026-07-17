"""TG05 -- Cross-Agent Privilege Inheritance.

Ported from ``packages/toolgovern/src/classifier/cross-agent-inheritance.ts``.

A sub-agent's own declared scope is not what governs it -- what its coordinator actually granted
at spawn time is. These rules compare the call's target resource against the ``ScopeRegistry``
record for the calling agent: ``requested_scope`` (what the sub-agent itself declares) versus
``granted_scope`` (what the coordinator's own scope actually allowed after default-deny
inheritance). A call that would be permitted under ``requested_scope`` but falls outside
``granted_scope`` is a privilege-inheritance violation, even if it looks fine in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional

from ..shared.paths import credential_matches_granted, host_matches_allowed, is_path_within
from ..scoping.inheritance_enforcer import has_zero_capability
from ..types import RuleContext, RuleMatch
from .util import extract_candidate_host, extract_credential_identifier, extract_path

_CATEGORY = "TG05"


@dataclass
class _Rule:
    id: str
    category: str
    description: str
    _evaluate: Callable[[RuleContext], Optional[RuleMatch]]

    def evaluate(self, ctx: RuleContext) -> Optional[RuleMatch]:
        return self._evaluate(ctx)


def _match(rule_id: str, decision: str, reason: str, matched_argument: str) -> RuleMatch:
    return RuleMatch(
        rule_id=rule_id,
        category=_CATEGORY,  # type: ignore[arg-type]
        decision=decision,  # type: ignore[arg-type]
        reason=reason,
        matched_argument=matched_argument,
    )


def _is_network_covered(host: str, network) -> bool:
    if network is True:
        return True
    if network is False:
        return False
    return any(host_matches_allowed(host, allowed) for allowed in network)


def _unregistered_sub_agent_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    if not ctx.coordinator_id:
        return None
    if not ctx.scope_registry:
        return None
    record = ctx.scope_registry.get_record(ctx.agent_id)
    if record:
        return None
    return _match(
        "TG05-unregistered-sub-agent",
        "deny",
        f'Agent "{ctx.agent_id}" declares coordinator "{ctx.coordinator_id}" but has no registered scope grant.',
        ctx.agent_id,
    )


def _zero_capability_sub_agent_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    if not ctx.coordinator_id:
        return None
    if not ctx.scope_registry:
        return None
    record = ctx.scope_registry.get_record(ctx.agent_id)
    if not record or not record.coordinator_id:
        return None
    if not has_zero_capability(record.granted_scope):
        return None
    return _match(
        "TG05-zero-capability-sub-agent",
        "deny",
        f'Agent "{ctx.agent_id}" was granted zero tool capability by its coordinator "{record.coordinator_id}"; all tool calls are denied.',
        ctx.agent_id,
    )


def _network_exceeds_grant_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    record = ctx.scope_registry.get_record(ctx.agent_id) if ctx.scope_registry else None
    if not record or not record.requested_scope:
        return None
    host = extract_candidate_host(ctx.args)
    if not host:
        return None
    requested_covers = _is_network_covered(host, record.requested_scope.network)
    granted_covers = _is_network_covered(host, record.granted_scope.network)
    if not requested_covers or granted_covers:
        return None
    return _match(
        "TG05-network-exceeds-grant",
        "deny",
        f'Host "{host}" was requested by "{ctx.agent_id}" but never granted by its coordinator.',
        host,
    )


def _filesystem_exceeds_grant_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    record = ctx.scope_registry.get_record(ctx.agent_id) if ctx.scope_registry else None
    if not record or not record.requested_scope:
        return None
    path = extract_path(ctx.args)
    if not path:
        return None
    requested_covers = any(is_path_within(path, prefix) for prefix in record.requested_scope.filesystem)
    granted_covers = any(is_path_within(path, prefix) for prefix in record.granted_scope.filesystem)
    if not requested_covers or granted_covers:
        return None
    return _match(
        "TG05-filesystem-exceeds-grant",
        "deny",
        f'Path "{path}" was requested by "{ctx.agent_id}" but never granted by its coordinator.',
        path,
    )


def _credential_exceeds_grant_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    record = ctx.scope_registry.get_record(ctx.agent_id) if ctx.scope_registry else None
    if not record or not record.requested_scope:
        return None
    identifier = extract_credential_identifier(ctx.args)
    if not identifier:
        return None
    requested_covers = any(
        credential_matches_granted(identifier, c) for c in record.requested_scope.credentials
    )
    granted_covers = any(credential_matches_granted(identifier, c) for c in record.granted_scope.credentials)
    if not requested_covers or granted_covers:
        return None
    return _match(
        "TG05-credential-exceeds-grant",
        "deny",
        f'Credential "{identifier}" was requested by "{ctx.agent_id}" but never granted by its coordinator.',
        identifier,
    )


def _coordinator_scope_shrunk_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    record = ctx.scope_registry.get_record(ctx.agent_id) if ctx.scope_registry else None
    if not record or not record.coordinator_id or not ctx.scope_registry:
        return None
    coordinator_record = ctx.scope_registry.get_record(record.coordinator_id)
    if not coordinator_record:
        return None

    path = extract_path(ctx.args)
    host = extract_candidate_host(ctx.args)
    identifier = extract_credential_identifier(ctx.args)

    if path:
        still_granted_by_self = any(is_path_within(path, p) for p in record.granted_scope.filesystem)
        coordinator_still_has_it = any(
            is_path_within(path, p) for p in coordinator_record.granted_scope.filesystem
        )
        if still_granted_by_self and not coordinator_still_has_it:
            return _match(
                "TG05-coordinator-scope-shrunk",
                "deny",
                f'Coordinator "{record.coordinator_id}" no longer covers path "{path}" it previously granted to "{ctx.agent_id}".',
                path,
            )
    if host:
        still_granted_by_self = _is_network_covered(host, record.granted_scope.network)
        coordinator_still_has_it = _is_network_covered(host, coordinator_record.granted_scope.network)
        if still_granted_by_self and not coordinator_still_has_it:
            return _match(
                "TG05-coordinator-scope-shrunk",
                "deny",
                f'Coordinator "{record.coordinator_id}" no longer covers host "{host}" it previously granted to "{ctx.agent_id}".',
                host,
            )
    if identifier:
        still_granted_by_self = any(
            credential_matches_granted(identifier, c) for c in record.granted_scope.credentials
        )
        coordinator_still_has_it = any(
            credential_matches_granted(identifier, c) for c in coordinator_record.granted_scope.credentials
        )
        if still_granted_by_self and not coordinator_still_has_it:
            return _match(
                "TG05-coordinator-scope-shrunk",
                "deny",
                f'Coordinator "{record.coordinator_id}" no longer covers credential "{identifier}" it previously granted to "{ctx.agent_id}".',
                identifier,
            )
    return None


cross_agent_inheritance_rules: List[_Rule] = [
    _Rule("TG05-unregistered-sub-agent", _CATEGORY, "A call arrives from a sub-agent with no verifiable spawn-time grant on record.", _unregistered_sub_agent_evaluate),
    _Rule(
        "TG05-zero-capability-sub-agent",
        _CATEGORY,
        "A sub-agent whose coordinator granted it zero capability at all attempts a tool call. Denied outright.",
        _zero_capability_sub_agent_evaluate,
    ),
    _Rule("TG05-network-exceeds-grant", _CATEGORY, "Target host is within the agent's own request but outside what its coordinator granted.", _network_exceeds_grant_evaluate),
    _Rule("TG05-filesystem-exceeds-grant", _CATEGORY, "Target path is within the agent's own request but outside what its coordinator granted.", _filesystem_exceeds_grant_evaluate),
    _Rule("TG05-credential-exceeds-grant", _CATEGORY, "Target credential is within the agent's own request but outside what its coordinator granted.", _credential_exceeds_grant_evaluate),
    _Rule(
        "TG05-coordinator-scope-shrunk",
        _CATEGORY,
        "The coordinator's own current scope no longer covers what it granted this sub-agent at spawn time.",
        _coordinator_scope_shrunk_evaluate,
    ),
]
