import { describe, expect, it } from 'vitest';
import { filesystemScopeRules } from '../../src/classifier/filesystem-scope.js';
import type { RuleContext } from '../../src/types.js';

function ctx(
  args: Record<string, unknown>,
  filesystem: readonly string[] = ['./workspace'],
): RuleContext {
  return {
    agentId: 'agent-1',
    sessionId: 'session-1',
    tool: 'fs.write',
    args,
    scope: { network: false, filesystem, credentials: [] },
  };
}

function fires(
  ruleId: string,
  args: Record<string, unknown>,
  filesystem?: readonly string[],
): boolean {
  const rule = filesystemScopeRules.find((r) => r.id === ruleId);
  if (!rule) throw new Error(`No such rule: ${ruleId}`);
  return rule.evaluate(ctx(args, filesystem)) !== null;
}

describe('TG02 filesystem scope escalation', () => {
  describe('TG02-write-outside-scope', () => {
    it('flags a write outside the declared prefix', () =>
      expect(
        fires('TG02-write-outside-scope', { path: '/tmp/export.csv', operation: 'write' }),
      ).toBe(true));
    it('flags a create outside scope', () =>
      expect(fires('TG02-write-outside-scope', { path: '/etc/hosts', operation: 'create' })).toBe(
        true,
      ));
    it('flags append outside scope', () =>
      expect(
        fires('TG02-write-outside-scope', { path: '/var/log/app.log', operation: 'append' }),
      ).toBe(true));
    it('does not flag a write inside the declared prefix', () =>
      expect(
        fires('TG02-write-outside-scope', { path: './workspace/out.txt', operation: 'write' }),
      ).toBe(false));
    it('does not flag a write at exactly the declared prefix', () =>
      expect(fires('TG02-write-outside-scope', { path: './workspace', operation: 'write' })).toBe(
        false,
      ));
    it('does not flag a read outside scope (not a write op)', () =>
      expect(
        fires('TG02-write-outside-scope', { path: '/tmp/export.csv', operation: 'read' }),
      ).toBe(false));
  });

  describe('TG02-delete-outside-scope', () => {
    it('flags delete outside scope', () =>
      expect(fires('TG02-delete-outside-scope', { path: '/etc/passwd', operation: 'delete' })).toBe(
        true,
      ));
    it('flags rm outside scope', () =>
      expect(fires('TG02-delete-outside-scope', { path: '/var/data', operation: 'rm' })).toBe(
        true,
      ));
    it('flags unlink outside scope', () =>
      expect(
        fires('TG02-delete-outside-scope', { path: '/home/user/file', operation: 'unlink' }),
      ).toBe(true));
    it('does not flag delete inside scope', () =>
      expect(
        fires('TG02-delete-outside-scope', { path: './workspace/tmp.txt', operation: 'delete' }),
      ).toBe(false));
    it('does not flag write outside scope (not a delete op)', () =>
      expect(fires('TG02-delete-outside-scope', { path: '/etc/passwd', operation: 'write' })).toBe(
        false,
      ));
  });

  describe('TG02-chmod-outside-scope', () => {
    it('flags chmod outside scope', () =>
      expect(fires('TG02-chmod-outside-scope', { path: '/usr/bin/sudo', operation: 'chmod' })).toBe(
        true,
      ));
    it('flags chown outside scope', () =>
      expect(fires('TG02-chmod-outside-scope', { path: '/etc/shadow', operation: 'chown' })).toBe(
        true,
      ));
    it('does not flag chmod inside scope', () =>
      expect(
        fires('TG02-chmod-outside-scope', { path: './workspace/run.sh', operation: 'chmod' }),
      ).toBe(false));
  });

  describe('TG02-path-traversal', () => {
    it('flags a path with .. segments', () =>
      expect(
        fires('TG02-path-traversal', { path: './workspace/../../etc/passwd', operation: 'write' }),
      ).toBe(true));
    it('flags a bare traversal path', () =>
      expect(fires('TG02-path-traversal', { path: '../../secrets', operation: 'read' })).toBe(
        true,
      ));
    it('does not flag a clean nested path', () =>
      expect(
        fires('TG02-path-traversal', { path: './workspace/sub/dir/file.txt', operation: 'write' }),
      ).toBe(false));
  });

  describe('TG02-symlink-escape', () => {
    it('flags a symlink target outside scope', () =>
      expect(fires('TG02-symlink-escape', { path: '/etc/passwd', operation: 'symlink' })).toBe(
        true,
      ));
    it('does not flag a symlink target inside scope', () =>
      expect(fires('TG02-symlink-escape', { path: './workspace/link', operation: 'symlink' })).toBe(
        false,
      ));
    it('does not flag a non-symlink operation', () =>
      expect(fires('TG02-symlink-escape', { path: '/etc/passwd', operation: 'write' })).toBe(
        false,
      ));
  });

  describe('TG02-sensitive-system-path', () => {
    it('flags a write to /etc', () =>
      expect(
        fires('TG02-sensitive-system-path', { path: '/etc/passwd', operation: 'write' }, ['/etc']),
      ).toBe(true));
    it('flags a delete under /usr', () =>
      expect(
        fires('TG02-sensitive-system-path', { path: '/usr/bin/node', operation: 'delete' }, [
          '/usr',
        ]),
      ).toBe(true));
    it('does not flag a write under an allowed workspace prefix', () =>
      expect(
        fires('TG02-sensitive-system-path', { path: './workspace/file', operation: 'write' }),
      ).toBe(false));
  });

  it('every rule has a unique id and belongs to TG02', () => {
    const ids = new Set(filesystemScopeRules.map((r) => r.id));
    expect(ids.size).toBe(filesystemScopeRules.length);
    for (const rule of filesystemScopeRules) {
      expect(rule.category).toBe('TG02');
    }
  });
});
