/**
 * Default-deny scope inheritance.
 *
 * When a coordinator agent spawns a sub-agent, the sub-agent does NOT inherit the coordinator's
 * full access by default. Its scope is the intersection of what it requests and what the
 * coordinator itself actually has -- anything requested but not covered by the coordinator's own
 * scope is silently dropped, never silently granted. `ScopeRegistry` is the runtime home for
 * this: it records every agent's effective (granted) scope and re-checks it on every call a rule
 * evaluates, not just once at spawn time.
 */

import type { AgentScopeRecord, ScopeDeclaration, ScopeRegistryReader } from '../types.js';
import { credentialMatchesGranted, hostMatchesAllowed, isPathWithin } from '../shared/paths.js';
import { EMPTY_SCOPE } from './scope-declaration.js';

function intersectNetwork(
  coordinator: ScopeDeclaration['network'],
  requested: ScopeDeclaration['network'],
): ScopeDeclaration['network'] {
  if (coordinator === false || requested === false) return false;
  if (coordinator === true && requested === true) return true;
  const coordinatorList = coordinator === true ? null : coordinator;
  const requestedList = requested === true ? null : requested;
  if (coordinatorList === null) return requestedList ?? [];
  if (requestedList === null) return coordinatorList;
  // For each (coordinator, requested) pair that are the same host or one is a subdomain of
  // the other, grant the NARROWER of the two -- not unconditionally whichever list's entry
  // matched. Filtering only the coordinator list (the original bug) grants a sub-agent that
  // asked for a narrow host (`api.example.com`) the coordinator's much broader entry
  // (`example.com`) whenever the broader entry's domain happens to cover the narrow request.
  // Filtering only the requested list would fix that case but breaks the opposite one: a
  // sub-agent that broadly requests `example.com` while the coordinator holds both
  // `example.com` and a narrower `api.example.com` should still receive the narrower
  // `api.example.com` grant intact (it's covered by the broad request, not widened by it).
  const granted = new Set<string>();
  for (const coordHost of coordinatorList) {
    for (const reqHost of requestedList) {
      if (coordHost === reqHost) {
        granted.add(coordHost);
      } else if (hostMatchesAllowed(coordHost, reqHost)) {
        granted.add(coordHost); // coordinator's entry is the narrower (subdomain) value
      } else if (hostMatchesAllowed(reqHost, coordHost)) {
        granted.add(reqHost); // requested entry is the narrower (subdomain) value
      }
    }
  }
  return Array.from(granted);
}

function intersectFilesystem(
  coordinator: readonly string[],
  requested: readonly string[],
): readonly string[] {
  return requested.filter((reqPath) =>
    coordinator.some((coordPath) => isPathWithin(reqPath, coordPath)),
  );
}

function intersectCredentials(
  coordinator: readonly string[],
  requested: readonly string[],
): readonly string[] {
  return requested.filter((reqCred) =>
    coordinator.some((coordCred) => credentialMatchesGranted(reqCred, coordCred)),
  );
}

/**
 * True if `scope` carries no capability at all -- no network access (`false`, or an allowlist
 * with zero entries -- both mean "cannot reach any host"), no filesystem prefix, and no
 * credential. An agent whose *granted* scope is this empty cannot legitimately make any tool
 * call, regardless of what the call's arguments happen to look like. This is distinct from an
 * agent that simply has no filesystem scope but does have network/credential access -- only the
 * fully-empty grant means "zero tool capability."
 */
export function hasZeroCapability(scope: ScopeDeclaration): boolean {
  const hasNetwork =
    scope.network === true || (Array.isArray(scope.network) && scope.network.length > 0);
  return !hasNetwork && scope.filesystem.length === 0 && scope.credentials.length === 0;
}

/**
 * Pure function: given a coordinator's own effective scope and a sub-agent's requested scope,
 * returns the scope actually granted. Never returns anything the coordinator itself does not
 * have, and never grants anything the sub-agent did not explicitly request.
 */
export function computeInheritedScope(
  coordinatorScope: ScopeDeclaration,
  requestedScope: ScopeDeclaration,
): ScopeDeclaration {
  return {
    network: intersectNetwork(coordinatorScope.network, requestedScope.network),
    filesystem: intersectFilesystem(coordinatorScope.filesystem, requestedScope.filesystem),
    credentials: intersectCredentials(coordinatorScope.credentials, requestedScope.credentials),
  };
}

export interface SpawnSubAgentParams {
  readonly coordinatorId: string;
  readonly subAgentId: string;
  readonly sessionId: string;
  readonly requestedScope: ScopeDeclaration;
}

/**
 * Tracks every agent's effective (granted) scope for a governed run. Root agents register their
 * own declared scope directly; sub-agents are spawned against a coordinator and receive the
 * intersection of what they request and what their coordinator actually has.
 */
export class ScopeRegistry implements ScopeRegistryReader {
  private readonly records = new Map<string, AgentScopeRecord>();

  registerRootAgent(agentId: string, sessionId: string, scope: ScopeDeclaration): AgentScopeRecord {
    const record: AgentScopeRecord = { agentId, sessionId, grantedScope: scope };
    this.records.set(agentId, record);
    return record;
  }

  /**
   * Spawns a sub-agent under `coordinatorId`. If the coordinator has never been registered, the
   * sub-agent is granted the empty scope -- default-deny applies even when the caller forgot to
   * register the coordinator first, rather than falling back to "unrestricted."
   */
  spawnSubAgent(params: SpawnSubAgentParams): AgentScopeRecord {
    const coordinatorRecord = this.records.get(params.coordinatorId);
    const coordinatorScope = coordinatorRecord?.grantedScope ?? EMPTY_SCOPE;
    const grantedScope = computeInheritedScope(coordinatorScope, params.requestedScope);
    const record: AgentScopeRecord = {
      agentId: params.subAgentId,
      sessionId: params.sessionId,
      coordinatorId: params.coordinatorId,
      requestedScope: params.requestedScope,
      grantedScope,
    };
    this.records.set(params.subAgentId, record);
    return record;
  }

  getRecord(agentId: string): AgentScopeRecord | undefined {
    return this.records.get(agentId);
  }

  getEffectiveScope(agentId: string): ScopeDeclaration | undefined {
    return this.records.get(agentId)?.grantedScope;
  }

  has(agentId: string): boolean {
    return this.records.has(agentId);
  }

  /**
   * True if `agentId` is registered and its granted scope has zero capability (see
   * `hasZeroCapability`). An unregistered agent is not "zero capability" here -- that case is
   * covered separately by `TG05-unregistered-sub-agent`, so this only reports on agents the
   * registry actually has a grant on record for, whether that grant came out empty at spawn time
   * or was reduced to empty by a later coordinator re-registration.
   */
  isZeroCapability(agentId: string): boolean {
    const record = this.records.get(agentId);
    return record !== undefined && hasZeroCapability(record.grantedScope);
  }
}
