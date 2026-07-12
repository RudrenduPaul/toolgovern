import { describe, expect, it } from 'vitest';
import {
  EMPTY_SCOPE,
  isValidAgentId,
  isValidScopeDeclaration,
  normalizeScope,
} from '../../src/scoping/scope-declaration.js';

describe('scope-declaration', () => {
  it('EMPTY_SCOPE denies everything', () => {
    expect(EMPTY_SCOPE.network).toBe(false);
    expect(EMPTY_SCOPE.filesystem).toHaveLength(0);
    expect(EMPTY_SCOPE.credentials).toHaveLength(0);
  });

  describe('isValidScopeDeclaration', () => {
    it('accepts a fully-formed scope', () => {
      expect(
        isValidScopeDeclaration({ network: false, filesystem: ['./workspace'], credentials: [] }),
      ).toBe(true);
    });

    it('accepts network as an allowlist array', () => {
      expect(
        isValidScopeDeclaration({ network: ['example.com'], filesystem: [], credentials: [] }),
      ).toBe(true);
    });

    it('rejects a missing filesystem field', () => {
      expect(isValidScopeDeclaration({ network: false, credentials: [] })).toBe(false);
    });

    it('rejects a non-array credentials field', () => {
      expect(isValidScopeDeclaration({ network: false, filesystem: [], credentials: 'all' })).toBe(
        false,
      );
    });

    it('rejects null', () => {
      expect(isValidScopeDeclaration(null)).toBe(false);
    });

    it('rejects a non-object', () => {
      expect(isValidScopeDeclaration('scope')).toBe(false);
    });
  });

  describe('normalizeScope', () => {
    it('fills in defaults for a fully-missing scope', () => {
      expect(normalizeScope(undefined)).toEqual(EMPTY_SCOPE);
    });

    it('preserves provided fields and defaults the rest', () => {
      expect(normalizeScope({ filesystem: ['./workspace'] })).toEqual({
        network: false,
        filesystem: ['./workspace'],
        credentials: [],
      });
    });
  });

  // `isValidAgentId` is format validation only -- it does NOT verify a caller actually is the
  // agent it claims to be (toolgovern has no cryptographic identity verification in v0.1; see
  // docs/security-model.md). These tests cover the narrow class of malformed input it does catch.
  describe('isValidAgentId', () => {
    it('accepts a plain well-formed identity string', () => {
      expect(isValidAgentId('coordinator')).toBe(true);
    });

    it('accepts a UUID-shaped identity', () => {
      expect(isValidAgentId('a1b2c3d4-e5f6-4789-a012-3456789abcde')).toBe(true);
    });

    it('accepts a namespaced identity with dots, colons, and slashes', () => {
      expect(isValidAgentId('org.team/research-sub:v2')).toBe(true);
    });

    it('accepts an identity at exactly the length ceiling (256 chars)', () => {
      expect(isValidAgentId('a'.repeat(256))).toBe(true);
    });

    it('rejects an empty string', () => {
      expect(isValidAgentId('')).toBe(false);
    });

    it('rejects a string one character past the length ceiling', () => {
      expect(isValidAgentId('a'.repeat(257))).toBe(false);
    });

    it('rejects a string containing an embedded null byte', () => {
      expect(isValidAgentId('agent\u0000-evil')).toBe(false);
    });

    it('rejects a string containing an embedded newline (log-injection shape)', () => {
      expect(isValidAgentId('agent\nfake_trace_line_injected')).toBe(false);
    });

    it('rejects a string containing an embedded carriage return', () => {
      expect(isValidAgentId('agent\rinjected')).toBe(false);
    });

    it('rejects a string containing a DEL control character', () => {
      expect(isValidAgentId('agent\u007Fname')).toBe(false);
    });

    it('rejects a string containing a Unicode line separator', () => {
      expect(isValidAgentId('agent\u2028name')).toBe(false);
    });

    it('rejects a string containing a Unicode paragraph separator', () => {
      expect(isValidAgentId('agent\u2029name')).toBe(false);
    });

    it('rejects a non-string value', () => {
      expect(isValidAgentId(12345)).toBe(false);
      expect(isValidAgentId(null)).toBe(false);
      expect(isValidAgentId(undefined)).toBe(false);
      expect(isValidAgentId({ id: 'coordinator' })).toBe(false);
    });
  });
});
