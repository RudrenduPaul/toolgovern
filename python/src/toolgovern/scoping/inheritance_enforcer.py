"""Default-deny scope inheritance.

Ported from ``packages/toolgovern/src/scoping/inheritance-enforcer.ts``.

When a coordinator agent spawns a sub-agent, the sub-agent does NOT inherit the coordinator's
full access by default. Its scope is the intersection of what it requests and what the
coordinator itself actually has -- anything requested but not covered by the coordinator's own
scope is silently dropped, never silently granted. ``ScopeRegistry`` is the runtime home for
this: it records every agent's effective (granted) scope and re-checks it on every call a rule
evaluates, not just once at spawn time.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from ..shared.paths import credential_matches_granted, host_matches_allowed, is_path_within
from ..types import AgentScopeRecord, ScopeDeclaration
from .scope_declaration import EMPTY_SCOPE


def _intersect_network(coordinator, requested):
    if coordinator is False or requested is False:
        return False
    if coordinator is True and requested is True:
        return True
    coordinator_list = None if coordinator is True else coordinator
    requested_list = None if requested is True else requested
    if coordinator_list is None:
        return list(requested_list) if requested_list is not None else []
    if requested_list is None:
        return list(coordinator_list)
    return [
        host
        for host in coordinator_list
        if any(host_matches_allowed(host, req) or host_matches_allowed(req, host) for req in requested_list)
    ]


def _intersect_filesystem(coordinator, requested):
    return [
        req_path for req_path in requested if any(is_path_within(req_path, coord_path) for coord_path in coordinator)
    ]


def _intersect_credentials(coordinator, requested):
    return [
        req_cred
        for req_cred in requested
        if any(credential_matches_granted(req_cred, coord_cred) for coord_cred in coordinator)
    ]


def has_zero_capability(scope: ScopeDeclaration) -> bool:
    """True if ``scope`` carries no capability at all -- no network access (False, or an
    allowlist with zero entries -- both mean "cannot reach any host"), no filesystem prefix,
    and no credential. An agent whose *granted* scope is this empty cannot legitimately make
    any tool call, regardless of what the call's arguments happen to look like."""
    has_network = scope.network is True or (isinstance(scope.network, (list, tuple)) and len(scope.network) > 0)
    return not has_network and len(scope.filesystem) == 0 and len(scope.credentials) == 0


def compute_inherited_scope(
    coordinator_scope: ScopeDeclaration, requested_scope: ScopeDeclaration
) -> ScopeDeclaration:
    """Pure function: given a coordinator's own effective scope and a sub-agent's requested
    scope, returns the scope actually granted. Never returns anything the coordinator itself
    does not have, and never grants anything the sub-agent did not explicitly request."""
    return ScopeDeclaration(
        network=_intersect_network(coordinator_scope.network, requested_scope.network),
        filesystem=_intersect_filesystem(coordinator_scope.filesystem, requested_scope.filesystem),
        credentials=_intersect_credentials(coordinator_scope.credentials, requested_scope.credentials),
    )


@dataclass(frozen=True)
class SpawnSubAgentParams:
    coordinator_id: str
    sub_agent_id: str
    session_id: str
    requested_scope: ScopeDeclaration


class ScopeRegistry:
    """Tracks every agent's effective (granted) scope for a governed run. Root agents register
    their own declared scope directly; sub-agents are spawned against a coordinator and receive
    the intersection of what they request and what their coordinator actually has."""

    def __init__(self) -> None:
        self._records: Dict[str, AgentScopeRecord] = {}

    def register_root_agent(self, agent_id: str, session_id: str, scope: ScopeDeclaration) -> AgentScopeRecord:
        record = AgentScopeRecord(agent_id=agent_id, session_id=session_id, granted_scope=scope)
        self._records[agent_id] = record
        return record

    def spawn_sub_agent(self, params: SpawnSubAgentParams) -> AgentScopeRecord:
        """Spawns a sub-agent under ``params.coordinator_id``. If the coordinator has never
        been registered, the sub-agent is granted the empty scope -- default-deny applies even
        when the caller forgot to register the coordinator first, rather than falling back to
        "unrestricted."."""
        coordinator_record = self._records.get(params.coordinator_id)
        coordinator_scope = coordinator_record.granted_scope if coordinator_record else EMPTY_SCOPE
        granted_scope = compute_inherited_scope(coordinator_scope, params.requested_scope)
        record = AgentScopeRecord(
            agent_id=params.sub_agent_id,
            session_id=params.session_id,
            coordinator_id=params.coordinator_id,
            requested_scope=params.requested_scope,
            granted_scope=granted_scope,
        )
        self._records[params.sub_agent_id] = record
        return record

    def get_record(self, agent_id: str) -> Optional[AgentScopeRecord]:
        return self._records.get(agent_id)

    def get_effective_scope(self, agent_id: str) -> Optional[ScopeDeclaration]:
        record = self._records.get(agent_id)
        return record.granted_scope if record else None

    def has(self, agent_id: str) -> bool:
        return agent_id in self._records

    def is_zero_capability(self, agent_id: str) -> bool:
        """True if ``agent_id`` is registered and its granted scope has zero capability. An
        unregistered agent is not "zero capability" here -- that case is covered separately by
        TG05-unregistered-sub-agent."""
        record = self._records.get(agent_id)
        return record is not None and has_zero_capability(record.granted_scope)
