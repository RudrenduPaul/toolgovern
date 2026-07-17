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

function decisionOf(
  ruleId: string,
  args: Record<string, unknown>,
  network: ScopeDeclaration['network'],
): string | undefined {
  const rule = networkEgressRules.find((r) => r.id === ruleId);
  if (!rule) throw new Error(`No such rule: ${ruleId}`);
  return rule.evaluate(ctx(args, network))?.decision;
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
    it('requires approval for a public IP literal, not deny', () =>
      expect(decisionOf('TG03-raw-ip-literal', { host: '203.0.113.5' }, ['example.com'])).toBe(
        'require-approval',
      ));

    describe('IPv6 literals', () => {
      it('flags a bracketed IPv6 loopback literal', () =>
        expect(fires('TG03-raw-ip-literal', { host: '[::1]' }, ['example.com'])).toBe(true));
      it('flags a bare IPv6 loopback literal', () =>
        expect(fires('TG03-raw-ip-literal', { host: '::1' }, ['example.com'])).toBe(true));
      it('flags an IPv6 link-local literal (fe80::/10)', () =>
        expect(fires('TG03-raw-ip-literal', { host: 'fe80::1' }, ['example.com'])).toBe(true));
      it('flags an IPv6 unique-local literal (fc00::/7)', () =>
        expect(fires('TG03-raw-ip-literal', { host: 'fc00::1' }, ['example.com'])).toBe(true));
      it('does not flag a domain name that merely contains colons in an unrelated field', () =>
        expect(fires('TG03-raw-ip-literal', { host: 'example.com' }, ['example.com'])).toBe(false));
    });

    describe('loopback/private/cloud-metadata targets are denied, not just flagged for approval', () => {
      it('denies the AWS/GCP/Azure cloud-metadata IPv4 address', () =>
        expect(
          decisionOf('TG03-raw-ip-literal', { host: '169.254.169.254' }, ['example.com']),
        ).toBe('deny'));
      it('denies the same metadata address in bare single-integer decimal form (2852039166 == 169.254.169.254)', () =>
        expect(
          decisionOf('TG03-raw-ip-literal', { host: '2852039166' }, ['example.com']),
        ).toBe('deny'));
      it('recognizes a decimal-encoded PUBLIC IP as an IP literal too (203.0.113.5 == 3405803781)', () =>
        // Sanity check that the decimal form is recognized as an IP literal in the first
        // place, not just for metadata/private targets: a decimal-encoded public address not
        // in scope still requires approval like its dotted-decimal equivalent would.
        expect(
          decisionOf('TG03-raw-ip-literal', { host: '3405803781' }, ['example.com']),
        ).toBe('require-approval'));
      it('denies an IPv4 loopback target', () =>
        expect(decisionOf('TG03-raw-ip-literal', { host: '127.0.0.1' }, ['example.com'])).toBe(
          'deny',
        ));
      it('denies an RFC1918 private IPv4 target', () =>
        expect(decisionOf('TG03-raw-ip-literal', { host: '10.0.0.5' }, ['example.com'])).toBe(
          'deny',
        ));
      it('denies an IPv6 loopback target', () =>
        expect(decisionOf('TG03-raw-ip-literal', { host: '::1' }, ['example.com'])).toBe('deny'));
      it('denies an IPv6 link-local target', () =>
        expect(decisionOf('TG03-raw-ip-literal', { host: 'fe80::1' }, ['example.com'])).toBe(
          'deny',
        ));
      it('denies an IPv4-mapped IPv6 literal that resolves into the metadata range', () =>
        expect(
          decisionOf('TG03-raw-ip-literal', { host: '::ffff:169.254.169.254' }, ['example.com']),
        ).toBe('deny'));
      it('still honors an explicit allowlist entry for a private IP, even though it is private', () =>
        expect(fires('TG03-raw-ip-literal', { host: '169.254.169.254' }, ['169.254.169.254'])).toBe(
          false,
        ));
    });
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

  describe('nested argument host extraction (SSRF via nested MCP tool payloads)', () => {
    it('finds a host buried one level deep in a nested object', () =>
      expect(
        fires('TG03-host-not-in-scope', { params: { url: 'https://attacker.io/x' } }, [
          'example.com',
        ]),
      ).toBe(true));
    it('finds a host buried several levels deep in nested objects', () =>
      expect(
        fires(
          'TG03-host-not-in-scope',
          { params: { target: { request: { host: 'attacker.io' } } } },
          ['example.com'],
        ),
      ).toBe(true));
    it('finds a host inside an array of nested tool-call payloads', () =>
      expect(
        fires(
          'TG03-host-not-in-scope',
          { calls: [{ name: 'noop' }, { args: { endpoint: 'attacker.io' } }] },
          ['example.com'],
        ),
      ).toBe(true));
    it('does not flag when the only nested host is allowlisted', () =>
      expect(
        fires('TG03-host-not-in-scope', { params: { url: 'https://api.example.com/x' } }, [
          'example.com',
        ]),
      ).toBe(false));
    it('still prefers a top-level explicit host over a nested one', () =>
      expect(
        fires(
          'TG03-host-not-in-scope',
          { url: 'https://api.example.com/x', params: { url: 'https://attacker.io/x' } },
          ['example.com'],
        ),
      ).toBe(false));
    it('flags a raw IP literal nested inside an MCP tool call payload', () =>
      expect(
        decisionOf(
          'TG03-raw-ip-literal',
          { toolCall: { params: { target: { host: '169.254.169.254' } } } },
          ['example.com'],
        ),
      ).toBe('deny'));
  });

  it('every rule has a unique id and belongs to TG03', () => {
    const ids = new Set(networkEgressRules.map((r) => r.id));
    expect(ids.size).toBe(networkEgressRules.length);
    for (const rule of networkEgressRules) {
      expect(rule.category).toBe('TG03');
    }
  });
});
