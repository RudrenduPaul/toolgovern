import { describe, expect, it } from 'vitest';
import { canonicalJson } from '../../src/trace/canonical-json.js';

describe('canonicalJson', () => {
  it('produces identical output regardless of key insertion order', () => {
    const a = canonicalJson({ b: 1, a: 2, c: { z: 1, y: 2 } });
    const b = canonicalJson({ a: 2, c: { y: 2, z: 1 }, b: 1 });
    expect(a).toBe(b);
  });

  it('preserves array order', () => {
    expect(canonicalJson([3, 1, 2])).toBe('[3,1,2]');
  });

  it('handles nested arrays of objects', () => {
    const result = canonicalJson([{ b: 1, a: 2 }]);
    expect(result).toBe('[{"a":2,"b":1}]');
  });

  it('passes through primitives and null', () => {
    expect(canonicalJson(null)).toBe('null');
    expect(canonicalJson(42)).toBe('42');
    expect(canonicalJson('x')).toBe('"x"');
  });
});
