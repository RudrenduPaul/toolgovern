import { describe, expect, it } from 'vitest';
import { networkEgressRules } from '../../src/classifier/network-egress.js';
import type { RuleContext, ScopeDeclaration } from '../../src/types.js';

function ctx(args: Record<string, unknown>, network: ScopeDeclaration['network']): RuleContext {
  return {
    agentId: 'agent-1',
    sessionId: 'session-1',
    tool: 'http.get',
    args,
    scope: { network, filesystem: [], credentials: [] },
  };
}

function fires(
  ruleId: string,
  args: Record<string, unknown>,
  network: ScopeDeclaration['network'],
): boolean {
  const rule = networkEgressRules.find((r) => r.id === ruleId);
  if (!rule) throw new Error(`No such rule: ${ruleId}`);
  return rule.evaluate(ctx(args, network)) !== null;
}

describe('TG03 undeclared network egress', () => {
  describe('TG03-network-disabled', () => {
    it('flags any host when network scope is false', () =>
      expect(fires('TG03-network-disabled', { url: 'https://example.com' }, false)).toBe(true));
    it('does not flag when network scope allows hosts', () =>
      expect(fires('TG03-network-disabled', { url: 'https://example.com' }, ['example.com'])).toBe(
        false,
      ));
    it('does not flag a call with no host at all', () =>
      expect(fires('TG03-network-disabled', { command: 'ls' }, false)).toBe(false));
  });

  describe('TG03-host-not-in-scope', () => {
    it('flags a host not in the allowlist', () =>
      expect(
        fires('TG03-host-not-in-scope', { url: 'https://attacker.io/x' }, ['example.com']),
      ).toBe(true));
    it('does not flag an allowlisted host', () =>
      expect(
        fires('TG03-host-not-in-scope', { url: 'https://api.example.com/x' }, ['example.com']),
      ).toBe(false));
    it('does not flag when network is unrestricted (true)', () =>
      expect(fires('TG03-host-not-in-scope', { url: 'https://anywhere.io' }, true)).toBe(false));
    it('does not evaluate when network scope is false (owned by TG03-network-disabled)', () =>
      expect(fires('TG03-host-not-in-scope', { url: 'https://anywhere.io' }, false)).toBe(false));
  });

  describe('TG03-raw-ip-literal', () => {
    it('flags a raw IP literal target', () =>
      expect(fires('TG03-raw-ip-literal', { host: '203.0.113.5' }, ['example.com'])).toBe(true));
    it('does not flag a domain name', () =>
      expect(fires('TG03-raw-ip-literal', { host: 'example.com' }, ['example.com'])).toBe(false));
    it('does not flag an allowlisted IP literal', () =>
      expect(fires('TG03-raw-ip-literal', { host: '203.0.113.5' }, ['203.0.113.5'])).toBe(false));
  });

  describe('TG03-non-standard-port', () => {
    it('flags a non-standard port on an unlisted host', () =>
      expect(fires('TG03-non-standard-port', { host: 'attacker.io:4444' }, ['example.com'])).toBe(
        true,
      ));
    it('does not flag port 443', () =>
      expect(fires('TG03-non-standard-port', { host: 'example.com:443' }, ['example.com'])).toBe(
        false,
      ));
    it('does not flag a host with no port', () =>
      expect(fires('TG03-non-standard-port', { host: 'example.com' }, ['example.com'])).toBe(
        false,
      ));
  });

  describe('TG03-dns-exfil-pattern', () => {
    it('flags a very long subdomain label', () =>
      expect(
        fires('TG03-dns-exfil-pattern', { host: `${'a'.repeat(50)}.attacker.io` }, false),
      ).toBe(true));
    it('does not flag a normal short subdomain', () =>
      expect(fires('TG03-dns-exfil-pattern', { host: 'api.example.com' }, false)).toBe(false));
  });

  describe('TG03-known-paste-relay', () => {
    it('flags pastebin-mirror.io', () =>
      expect(
        fires('TG03-known-paste-relay', { url: 'https://pastebin-mirror.io/raw/8x2k' }, false),
      ).toBe(true));
    it('flags webhook.site', () =>
      expect(fires('TG03-known-paste-relay', { url: 'https://webhook.site/abc' }, false)).toBe(
        true,
      ));
    it('does not flag an unrelated domain', () =>
      expect(fires('TG03-known-paste-relay', { url: 'https://example.com/data' }, false)).toBe(
        false,
      ));
    it('does not flag a relay domain explicitly allowlisted', () =>
      expect(
        fires('TG03-known-paste-relay', { url: 'https://transfer.sh/abc' }, ['transfer.sh']),
      ).toBe(false));
  });

  it('every rule has a unique id and belongs to TG03', () => {
    const ids = new Set(networkEgressRules.map((r) => r.id));
    expect(ids.size).toBe(networkEgressRules.length);
    for (const rule of networkEgressRules) {
      expect(rule.category).toBe('TG03');
    }
  });
});
