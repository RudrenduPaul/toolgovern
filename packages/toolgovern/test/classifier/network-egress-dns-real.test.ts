/**
 * TG03-dns-resolves-private exercised against the REAL OS resolver (`dns.promises.lookup`,
 * unmocked) -- deliberately kept in its own file so `node:dns` is never mocked here, unlike
 * `network-egress.test.ts`'s deterministic metadata/cloud-IP cases (which mock the resolver since
 * there is no real hostname anyone can rely on always resolving to `169.254.169.254`).
 *
 * `localhost` is the one hostname genuinely safe to assert on across CI/sandbox environments
 * without any network access at all: every POSIX system's `/etc/hosts` (and Windows'
 * `%SystemRoot%\System32\drivers\etc\hosts`) maps it to `127.0.0.1` (and usually `::1`), and
 * `dns.promises.lookup()` honors `/etc/hosts` before ever making a network round-trip -- so this
 * genuinely proves the resolve-then-check path works end-to-end, not just against a stub.
 */
import { describe, expect, it } from 'vitest';
import { networkEgressAsyncRules } from '../../src/classifier/network-egress.js';
import type { RuleContext } from '../../src/types.js';

function ctx(host: string): RuleContext {
  return {
    agentId: 'agent-1',
    sessionId: 'session-1',
    tool: 'http.get',
    args: { host },
    scope: { network: ['other.example'], filesystem: [], credentials: [] },
  };
}

const dnsRule = networkEgressAsyncRules.find((r) => r.id === 'TG03-dns-resolves-private');
if (!dnsRule) throw new Error('No such async rule: TG03-dns-resolves-private');

describe('TG03-dns-resolves-private against the real OS resolver (node:dns, not mocked)', () => {
  it('denies "localhost" -- resolves via a real /etc/hosts-backed lookup to 127.0.0.1 (and/or ::1)', async () => {
    const result = await dnsRule.evaluateAsync(ctx('localhost'));
    expect(result?.decision).toBe('deny');
    expect(result?.ruleId).toBe('TG03-dns-resolves-private');
    // Whichever family the OS resolver returned first, the match reason names a real loopback
    // address -- not a fabricated/mocked one.
    expect(result?.reason).toMatch(/127\.0\.0\.1|::1/);
  });

  it('fails CLOSED (require-approval) for a hostname the real resolver cannot resolve at all', async () => {
    // RFC 2606 reserves the .invalid TLD specifically so it is guaranteed to never resolve --
    // this is a genuine resolution failure against the real resolver, not a simulated one.
    const result = await dnsRule.evaluateAsync(ctx('this-host-genuinely-does-not-exist.invalid'));
    expect(result?.decision).toBe('require-approval');
    expect(result?.reason.toLowerCase()).toMatch(/failed|no addresses|timed out/);
  }, 10_000);
});
