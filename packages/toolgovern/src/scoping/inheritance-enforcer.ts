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
  return coordinatorList.filter((host) =>
    requestedList.some((req) => hostMatchesAllowed(host, req) || hostMatchesAllowed(req, host)),
  );
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
}
