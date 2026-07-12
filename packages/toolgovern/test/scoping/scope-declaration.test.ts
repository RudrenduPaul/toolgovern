import { describe, expect, it } from 'vitest';
import {
  EMPTY_SCOPE,
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
});
