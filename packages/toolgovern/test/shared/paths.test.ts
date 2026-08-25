import { describe, expect, it } from 'vitest';
import { containsPathTraversal, isPathWithin, normalizePath } from '../../src/shared/paths.js';

describe('normalizePath / isPathWithin / containsPathTraversal - backslash handling (2026-08-24 security fix)', () => {
  // Previously these helpers only split on `/`, so a backslash-delimited ".." segment was
  // invisible to `containsPathTraversal`, and a scope prefix like `/allowed` would treat any
  // candidate that merely started with the literal string "/allowed/" as in-scope even when the
  // remainder was pure backslash-delimited traversal (`/allowed/sub\..\..\..\secrets`). This
  // undercut the "sub-agent can't reach outside its declared scope" guarantee identically across
  // the TypeScript, Python, and .NET ports.

  it('normalizePath converts backslashes to forward slashes', () => {
    expect(normalizePath('workspace\\sub\\file.txt')).toBe('workspace/sub/file.txt');
  });

  it('normalizePath collapses a mix of backslashes and forward slashes consistently', () => {
    expect(normalizePath('./workspace\\sub/../file.txt')).toBe('workspace/sub/../file.txt');
  });

  it('containsPathTraversal detects a ".." segment delimited by backslashes', () => {
    expect(containsPathTraversal('sub\\..\\..\\..\\secrets')).toBe(true);
  });

  it('containsPathTraversal detects a ".." segment in a mixed-separator path', () => {
    expect(containsPathTraversal('sub/..\\../secrets')).toBe(true);
  });

  it('containsPathTraversal still returns false for a clean backslash path with no ".." segments', () => {
    expect(containsPathTraversal('workspace\\sub\\file.txt')).toBe(false);
  });

  it('containsPathTraversal still detects the original forward-slash-only case (no regression)', () => {
    expect(containsPathTraversal('../../etc/passwd')).toBe(true);
  });

  it('isPathWithin still recognizes a genuine nested path as in scope', () => {
    expect(isPathWithin('/allowed/sub/dir/file.txt', '/allowed')).toBe(true);
  });

  it('isPathWithin still rejects an unrelated path as out of scope', () => {
    expect(isPathWithin('/other/dir/file.txt', '/allowed')).toBe(false);
  });
});
