import { describe, expect, it } from 'vitest';
import { validatePolicy } from '../../src/policy/validatePolicy.js';

describe('validatePolicy', () => {
  it('accepts a minimal valid policy', () => {
    const result = validatePolicy({
      name: 'strict-shell',
      scope: { network: false, filesystem: ['./workspace'], credentials: [] },
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('accepts rule overrides that reference real rule IDs', () => {
    const result = validatePolicy({
      name: 'strict-shell',
      scope: { network: false, filesystem: [], credentials: [] },
      rules: { disable: ['TG01-sudo'], requireApproval: ['TG01-rm-rf'] },
    });
    expect(result.valid).toBe(true);
  });

  it('rejects a policy with no scope', () => {
    const result = validatePolicy({ name: 'no-scope' });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('scope'))).toBe(true);
  });

  it('rejects a rule override referencing an unknown rule ID', () => {
    const result = validatePolicy({
      name: 'strict-shell',
      scope: { network: false, filesystem: [], credentials: [] },
      rules: { disable: ['TG99-not-real'] },
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('TG99-not-real'))).toBe(true);
  });

  it('rejects an invalid defaultDecision', () => {
    const result = validatePolicy({
      name: 'strict-shell',
      scope: { network: false, filesystem: [], credentials: [] },
      defaultDecision: 'maybe',
    });
    expect(result.valid).toBe(false);
  });

  it('rejects a top-level non-object', () => {
    const result = validatePolicy('not-an-object');
    expect(result.valid).toBe(false);
  });

  it('rejects a top-level array', () => {
    const result = validatePolicy([1, 2, 3]);
    expect(result.valid).toBe(false);
  });

  it('rejects a malformed rules field', () => {
    const result = validatePolicy({
      name: 'x',
      scope: { network: false, filesystem: [], credentials: [] },
      rules: 'not-an-object',
    });
    expect(result.valid).toBe(false);
  });

  it('rejects a non-array rules.disable', () => {
    const result = validatePolicy({
      name: 'x',
      scope: { network: false, filesystem: [], credentials: [] },
      rules: { disable: 'TG01-sudo' },
    });
    expect(result.valid).toBe(false);
  });

  it('collects multiple errors at once', () => {
    const result = validatePolicy({ defaultDecision: 'maybe' });
    expect(result.errors.length).toBeGreaterThan(1);
  });
});
