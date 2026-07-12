/**
 * TG03 -- Undeclared Network Egress
 *
 * Fires when a call reaches a host not present in the caller's declared network scope
 * (`scope.network`: `false` for no access, `true` for unrestricted, or an explicit host
 * allowlist).
 */

import type { Rule, RuleContext, RuleMatch } from '../types.js';
import { hostMatchesAllowed, isIpLiteral, isPrivateOrMetadataTarget } from '../shared/paths.js';
import { extractCandidateHost, extractCommand, extractHost } from './util.js';

const category = 'TG03' as const;

const KNOWN_RELAY_DOMAINS = [
  'pastebin.com',
  'pastebin-mirror.io',
  'transfer.sh',
  'ngrok.io',
  'ngrok-free.app',
  'requestbin.com',
  'webhook.site',
  'file.io',
];

function match(
  rule: Pick<Rule, 'id' | 'category'>,
  decision: RuleMatch['decision'],
  reason: string,
  matchedArgument: string,
): RuleMatch {
  return { ruleId: rule.id, category: rule.category, decision, reason, matchedArgument };
}

function isHostInScope(host: string, network: RuleContext['scope']['network']): boolean {
  if (network === true) return true;
  if (network === false) return false;
  return network.some((allowed) => hostMatchesAllowed(host, allowed));
}

const networkDisabled: Rule = {
  id: 'TG03-network-disabled',
  category,
  description: 'Any network egress attempted while the agent has no network scope at all.',
  evaluate(ctx) {
    if (ctx.scope.network !== false) return null;
    const host = extractCandidateHost(ctx.args);
    if (!host) return null;
    return match(
      this,
      'deny',
      `Network call to "${host}" attempted with network scope disabled.`,
      host,
    );
  },
};

const hostNotInScope: Rule = {
  id: 'TG03-host-not-in-scope',
  category,
  description: 'The target host is not present in the declared network allowlist.',
  evaluate(ctx) {
    if (ctx.scope.network === false || ctx.scope.network === true) return null;
    const host = extractCandidateHost(ctx.args);
    if (!host) return null;
    if (isHostInScope(host, ctx.scope.network)) return null;
    return match(this, 'deny', `Host "${host}" is not in the declared network allowlist.`, host);
  },
};

const rawIpLiteral: Rule = {
  id: 'TG03-raw-ip-literal',
  category,
  description: 'Connection to a raw IP literal, bypassing a domain-based allowlist.',
  evaluate(ctx) {
    const host = extractCandidateHost(ctx.args);
    if (!host || !isIpLiteral(host)) return null;
    if (ctx.scope.network === true) return null;
    if (Array.isArray(ctx.scope.network) && ctx.scope.network.includes(host)) return null;
    if (isPrivateOrMetadataTarget(host)) {
      // Loopback, RFC1918/unique-local, link-local, and cloud-metadata targets (e.g.
      // `169.254.169.254`) are denied outright -- a human approver must never be able to
      // rubber-stamp a call into an internal network or a cloud metadata endpoint.
      return match(
        this,
        'deny',
        `Connection to loopback/private/cloud-metadata IP literal "${host}" is never approvable.`,
        host,
      );
    }
    return match(this, 'require-approval', `Connection to raw IP literal "${host}".`, host);
  },
};

const nonStandardPort: Rule = {
  id: 'TG03-non-standard-port',
  category,
  description: 'Connection to a non-standard port on a host outside the allowlist.',
  evaluate(ctx) {
    const raw = extractHost(ctx.args) ?? extractCommand(ctx.args) ?? '';
    const portMatch = raw.match(/:(\d{2,5})\b/);
    if (!portMatch) return null;
    const port = Number(portMatch[1]);
    if (port === 80 || port === 443) return null;
    const host = extractCandidateHost(ctx.args);
    if (!host) return null;
    if (ctx.scope.network === true) return null;
    if (Array.isArray(ctx.scope.network) && ctx.scope.network.includes(host)) return null;
    return match(
      this,
      'require-approval',
      `Connection to "${host}" on non-standard port ${port}.`,
      `${host}:${port}`,
    );
  },
};

const dnsExfilPattern: Rule = {
  id: 'TG03-dns-exfil-pattern',
  category,
  description: 'Suspiciously long, high-entropy subdomain label -- a common DNS-exfil shape.',
  evaluate(ctx) {
    const host = extractCandidateHost(ctx.args);
    if (!host) return null;
    const firstLabel = host.split('.')[0] ?? '';
    if (firstLabel.length < 40) return null;
    return match(this, 'require-approval', `Unusually long subdomain label on "${host}".`, host);
  },
};

const knownPasteRelay: Rule = {
  id: 'TG03-known-paste-relay',
  category,
  description: 'Target host matches a known paste/relay/tunnel service commonly used for exfil.',
  evaluate(ctx) {
    const host = extractCandidateHost(ctx.args);
    if (!host) return null;
    const hit = KNOWN_RELAY_DOMAINS.find(
      (domain) => host === domain || host.endsWith(`.${domain}`),
    );
    if (!hit) return null;
    if (Array.isArray(ctx.scope.network) && ctx.scope.network.includes(hit)) return null;
    return match(this, 'deny', `Host "${host}" matches known paste/relay service "${hit}".`, host);
  },
};

export const networkEgressRules: readonly Rule[] = [
  networkDisabled,
  hostNotInScope,
  rawIpLiteral,
  nonStandardPort,
  dnsExfilPattern,
  knownPasteRelay,
];
