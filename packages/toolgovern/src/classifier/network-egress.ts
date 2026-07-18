/**
 * TG03 -- Undeclared Network Egress
 *
 * Fires when a call reaches a host not present in the caller's declared network scope
 * (`scope.network`: `false` for no access, `true` for unrestricted, or an explicit host
 * allowlist).
 */

import { promises as dnsPromises } from 'node:dns';
import type { AsyncRule, Rule, RuleContext, RuleMatch } from '../types.js';
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
    // An explicit, exact allowlist entry for this host is honored even if it is private/
    // metadata -- that's a deliberate, specific operator decision (they named this exact
    // address), unlike the blanket `scope.network === true` grant checked below, which
    // incidentally covers everything including metadata endpoints without the operator ever
    // having considered this specific address.
    if (Array.isArray(ctx.scope.network) && ctx.scope.network.includes(host)) return null;
    if (isPrivateOrMetadataTarget(host)) {
      // Loopback, RFC1918/unique-local, link-local, and cloud-metadata targets (e.g.
      // `169.254.169.254`) are denied outright for any scope that did not explicitly name
      // this exact host above -- this check must run before the `scope.network === true`
      // early-return below, not after it: an agent with unrestricted (but not
      // host-specific) network access must still never be able to reach an internal
      // network or cloud-metadata endpoint via this rule. That's the entire point of
      // "never approvable" -- it cannot be conditional on a blanket `network: true` grant.
      return match(
        this,
        'deny',
        `Connection to loopback/private/cloud-metadata IP literal "${host}" is never approvable.`,
        host,
      );
    }
    if (ctx.scope.network === true) return null;
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

/** How long to wait for a DNS answer before treating the lookup as failed (and failing closed --
 *  see `dnsResolvesToPrivateTarget` below). A hung/unresponsive resolver must not be able to stall
 *  a tool call indefinitely, but this is generous enough to not misfire against a normally-slow
 *  but legitimate resolver. */
const DNS_LOOKUP_TIMEOUT_MS = 3_000;

/** Resolves every address a hostname maps to via the OS resolver (`dns.promises.lookup`, which
 *  also honors `/etc/hosts` -- so an operator-added `127.0.0.1  internal-alias` entry is caught
 *  exactly like a real DNS A/AAAA record would be), racing it against a hard timeout so a
 *  hung/unresponsive resolver cannot stall the call indefinitely. Rejects (never resolves to an
 *  empty allow-shaped value) on failure or timeout -- callers must treat a rejection as "unknown,
 *  fail closed," never as "no private address found." */
async function resolveHostAddresses(host: string): Promise<string[]> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`DNS lookup for "${host}" timed out after ${DNS_LOOKUP_TIMEOUT_MS}ms`));
    }, DNS_LOOKUP_TIMEOUT_MS);
  });
  try {
    const records = await Promise.race([dnsPromises.lookup(host, { all: true }), timeout]);
    return records.map((record) => record.address);
  } finally {
    clearTimeout(timer);
  }
}

const dnsResolvesToPrivateTarget: AsyncRule = {
  id: 'TG03-dns-resolves-private',
  category,
  description:
    'A hostname argument that resolves via DNS to a loopback/RFC1918/link-local/cloud-metadata ' +
    'address, even though the argument itself is a domain name, not a raw IP literal (the same ' +
    'target class `TG03-raw-ip-literal` already denies for literal IPs, extended to the ' +
    'DNS-resolution step raw-literal matching alone cannot see).',
  async evaluateAsync(ctx) {
    const host = extractCandidateHost(ctx.args);
    // A raw IP literal is already fully handled by TG03-raw-ip-literal; resolving it would be a
    // no-op (or, for a bare decimal-encoded literal, actively wrong) -- this rule only concerns
    // itself with actual hostnames.
    if (!host || isIpLiteral(host)) return null;
    // Mirrors TG03-raw-ip-literal's own carve-out: an explicit, exact allowlist entry for this
    // hostname is a deliberate, specific operator decision, honored even if it turns out to
    // resolve to a private address.
    if (Array.isArray(ctx.scope.network) && ctx.scope.network.includes(host)) return null;

    let addresses: string[];
    try {
      addresses = await resolveHostAddresses(host);
    } catch (error) {
      // Fail CLOSED on a DNS-resolution failure (NXDOMAIN, timeout, resolver error, whatever the
      // cause) -- an unresolvable host is never treated as "safe to allow." A `require-approval`
      // decision (not an automatic `allow`) is this rule's failure-mode convention, matching
      // `TG03-raw-ip-literal`'s use of `require-approval` for anything not affirmatively known to
      // be safe.
      const message = error instanceof Error ? error.message : String(error);
      return match(
        { id: 'TG03-dns-resolves-private', category },
        'require-approval',
        `DNS resolution for host "${host}" failed (${message}); failing closed rather than ` +
          'assuming an unresolvable host is safe to reach.',
        host,
      );
    }

    if (addresses.length === 0) {
      // Some resolvers return an empty record set rather than rejecting outright for an unknown
      // name -- treated identically to a resolution failure above, for the same fail-closed reason.
      return match(
        { id: 'TG03-dns-resolves-private', category },
        'require-approval',
        `DNS resolution for host "${host}" returned no addresses; failing closed rather than ` +
          'assuming an unresolvable host is safe to reach.',
        host,
      );
    }

    const privateAddress = addresses.find((address) => isPrivateOrMetadataTarget(address));
    if (!privateAddress) return null;

    return match(
      { id: 'TG03-dns-resolves-private', category },
      'deny',
      `Host "${host}" resolves via DNS to loopback/private/cloud-metadata address ` +
        `"${privateAddress}" -- denied even though the call argument is a hostname, not a raw IP ` +
        'literal. Residual limitation, disclosed rather than hidden: this is a resolve-then-check ' +
        'at classification time, not a connection-time guarantee -- it narrows but does not ' +
        "eliminate DNS-rebinding TOCTOU, since an attacker who controls this name's DNS answer " +
        'can still swap it to a private/internal address after this check runs and before the ' +
        "tool's own HTTP client actually connects. True TOCTOU-proof protection would require the " +
        "tool's own HTTP client to connect to this exact resolved+validated address (DNS pinning), " +
        'which a pre-execution argument gate like governTool() cannot enforce -- see ' +
        'docs/security-model.md.',
      host,
    );
  },
};

/** Async-only TG03 checks -- currently just DNS resolution of hostname arguments. Evaluated by
 *  `classifyAsync()` (`classifier/index.ts`), not by the synchronous `classify()`. See
 *  `dnsResolvesToPrivateTarget` for what this does and does not close. */
export const networkEgressAsyncRules: readonly AsyncRule[] = [dnsResolvesToPrivateTarget];
