/**
 * TG05 -- Cross-Agent Privilege Inheritance
 *
 * A sub-agent's own declared scope is not what governs it -- what its coordinator actually
 * granted at spawn time is. These rules compare the call's target resource against the
 * `ScopeRegistry` record for the calling agent: `requestedScope` (what the sub-agent itself
 * declares) versus `grantedScope` (what the coordinator's own scope actually allowed after
 * default-deny inheritance). A call that would be permitted under `requestedScope` but falls
 * outside `grantedScope` is a privilege-inheritance violation, even if it looks fine in
 * isolation.
 */

import type { Rule, RuleContext, RuleMatch } from '../types.js';
import { credentialMatchesGranted, hostMatchesAllowed, isPathWithin } from '../shared/paths.js';
import { extractCandidateHost, extractCredentialIdentifier, extractPath } from './util.js';

const category = 'TG05' as const;

function match(
  rule: Pick<Rule, 'id' | 'category'>,
  decision: RuleMatch['decision'],
  reason: string,
  matchedArgument: string,
): RuleMatch {
  return { ruleId: rule.id, category: rule.category, decision, reason, matchedArgument };
}

function isNetworkCovered(host: string, network: RuleContext['scope']['network']): boolean {
  if (network === true) return true;
  if (network === false) return false;
  return network.some((allowed) => hostMatchesAllowed(host, allowed));
}

const unregisteredSubAgent: Rule = {
  id: 'TG05-unregistered-sub-agent',
  category,
  description: 'A call arrives from a sub-agent with no verifiable spawn-time grant on record.',
  evaluate(ctx) {
    if (!ctx.coordinatorId) return null;
    if (!ctx.scopeRegistry) return null;
    const record = ctx.scopeRegistry.getRecord(ctx.agentId);
    if (record) return null;
    return match(
      this,
      'deny',
      `Agent "${ctx.agentId}" declares coordinator "${ctx.coordinatorId}" but has no registered scope grant.`,
      ctx.agentId,
    );
  },
};

const networkExceedsGrant: Rule = {
  id: 'TG05-network-exceeds-grant',
  category,
  description:
    "Target host is within the agent's own request but outside what its coordinator granted.",
  evaluate(ctx) {
    const record = ctx.scopeRegistry?.getRecord(ctx.agentId);
    if (!record?.requestedScope) return null;
    const host = extractCandidateHost(ctx.args);
    if (!host) return null;
    const requestedCovers = isNetworkCovered(host, record.requestedScope.network);
    const grantedCovers = isNetworkCovered(host, record.grantedScope.network);
    if (!requestedCovers || grantedCovers) return null;
    return match(
      this,
      'deny',
      `Host "${host}" was requested by "${ctx.agentId}" but never granted by its coordinator.`,
      host,
    );
  },
};

const filesystemExceedsGrant: Rule = {
  id: 'TG05-filesystem-exceeds-grant',
  category,
  description:
    "Target path is within the agent's own request but outside what its coordinator granted.",
  evaluate(ctx) {
    const record = ctx.scopeRegistry?.getRecord(ctx.agentId);
    if (!record?.requestedScope) return null;
    const path = extractPath(ctx.args);
    if (!path) return null;
    const requestedCovers = record.requestedScope.filesystem.some((prefix) =>
      isPathWithin(path, prefix),
    );
    const grantedCovers = record.grantedScope.filesystem.some((prefix) =>
      isPathWithin(path, prefix),
    );
    if (!requestedCovers || grantedCovers) return null;
    return match(
      this,
      'deny',
      `Path "${path}" was requested by "${ctx.agentId}" but never granted by its coordinator.`,
      path,
    );
  },
};

const credentialExceedsGrant: Rule = {
  id: 'TG05-credential-exceeds-grant',
  category,
  description:
    "Target credential is within the agent's own request but outside what its coordinator granted.",
  evaluate(ctx) {
    const record = ctx.scopeRegistry?.getRecord(ctx.agentId);
    if (!record?.requestedScope) return null;
    const identifier = extractCredentialIdentifier(ctx.args);
    if (!identifier) return null;
    const requestedCovers = record.requestedScope.credentials.some((c) =>
      credentialMatchesGranted(identifier, c),
    );
    const grantedCovers = record.grantedScope.credentials.some((c) =>
      credentialMatchesGranted(identifier, c),
    );
    if (!requestedCovers || grantedCovers) return null;
    return match(
      this,
      'deny',
      `Credential "${identifier}" was requested by "${ctx.agentId}" but never granted by its coordinator.`,
      identifier,
    );
  },
};

const coordinatorScopeShrunk: Rule = {
  id: 'TG05-coordinator-scope-shrunk',
  category,
  description:
    "The coordinator's own current scope no longer covers what it granted this sub-agent at spawn time.",
  evaluate(ctx) {
    const record = ctx.scopeRegistry?.getRecord(ctx.agentId);
    if (!record?.coordinatorId || !ctx.scopeRegistry) return null;
    const coordinatorRecord = ctx.scopeRegistry.getRecord(record.coordinatorId);
    if (!coordinatorRecord) return null;

    const path = extractPath(ctx.args);
    const host = extractCandidateHost(ctx.args);
    const identifier = extractCredentialIdentifier(ctx.args);

    if (path) {
      const stillGrantedBySelf = record.grantedScope.filesystem.some((p) => isPathWithin(path, p));
      const coordinatorStillHasIt = coordinatorRecord.grantedScope.filesystem.some((p) =>
        isPathWithin(path, p),
      );
      if (stillGrantedBySelf && !coordinatorStillHasIt) {
        return match(
          this,
          'deny',
          `Coordinator "${record.coordinatorId}" no longer covers path "${path}" it previously granted to "${ctx.agentId}".`,
          path,
        );
      }
    }
    if (host) {
      const stillGrantedBySelf = isNetworkCovered(host, record.grantedScope.network);
      const coordinatorStillHasIt = isNetworkCovered(host, coordinatorRecord.grantedScope.network);
      if (stillGrantedBySelf && !coordinatorStillHasIt) {
        return match(
          this,
          'deny',
          `Coordinator "${record.coordinatorId}" no longer covers host "${host}" it previously granted to "${ctx.agentId}".`,
          host,
        );
      }
    }
    if (identifier) {
      const stillGrantedBySelf = record.grantedScope.credentials.some((c) =>
        credentialMatchesGranted(identifier, c),
      );
      const coordinatorStillHasIt = coordinatorRecord.grantedScope.credentials.some((c) =>
        credentialMatchesGranted(identifier, c),
      );
      if (stillGrantedBySelf && !coordinatorStillHasIt) {
        return match(
          this,
          'deny',
          `Coordinator "${record.coordinatorId}" no longer covers credential "${identifier}" it previously granted to "${ctx.agentId}".`,
          identifier,
        );
      }
    }
    return null;
  },
};

export const crossAgentInheritanceRules: readonly Rule[] = [
  unregisteredSubAgent,
  networkExceedsGrant,
  filesystemExceedsGrant,
  credentialExceedsGrant,
  coordinatorScopeShrunk,
];
