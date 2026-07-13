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

    it('flags a write outside scope embedded in a `code` argument (inferred from open mode)', () =>
      expect(
        fires('TG02-write-outside-scope', { code: 'open("/tmp/export.csv", "w").write(data)' }),
      ).toBe(true));

    it('does not flag a write embedded in code that targets an in-scope path', () =>
      expect(
        fires('TG02-write-outside-scope', {
          code: 'open("./workspace/out.txt", "w").write(data)',
        }),
      ).toBe(false));

    it('does not flag a plain read embedded in code (no write-mode/write-call detected)', () => {
      // Uses a neutral tool name -- the shared `fires()` harness defaults to `fs.write`, whose
      // name alone would satisfy the rule's own "no operation found, but the tool name says
      // write" fallback and defeat the point of this test (that a code-embedded *read* isn't
      // misread as a write).
      const rule = filesystemScopeRules.find((r) => r.id === 'TG02-write-outside-scope')!;
      const readCtx: RuleContext = {
        agentId: 'agent-1',
        sessionId: 'session-1',
        tool: 'exec.run_code',
        args: { code: 'open("/tmp/export.csv").read()' },
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
      };
      expect(rule.evaluate(readCtx)).toBeNull();
    });
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

    it('flags a delete outside scope embedded in a `code` argument (os.remove)', () =>
      expect(
        fires('TG02-delete-outside-scope', { code: 'import os\nos.remove("/etc/passwd")' }),
      ).toBe(true));

    it('flags a delete outside scope embedded in a `code` argument (shutil.rmtree)', () =>
      expect(
        fires('TG02-delete-outside-scope', {
          code: 'import shutil\nshutil.rmtree("/var/data")',
        }),
      ).toBe(true));

    it('does not flag a delete embedded in code that targets an in-scope path', () =>
      expect(
        fires('TG02-delete-outside-scope', { code: 'import os\nos.remove("./workspace/tmp.txt")' }),
      ).toBe(false));
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

    it('flags a chmod outside scope embedded in a `code` argument (os.chmod)', () =>
      expect(
        fires('TG02-chmod-outside-scope', { code: 'import os\nos.chmod("/usr/bin/sudo", 0o777)' }),
      ).toBe(true));

    it('does not flag a chmod embedded in code that targets an in-scope path', () =>
      expect(
        fires('TG02-chmod-outside-scope', {
          code: 'import os\nos.chmod("./workspace/run.sh", 0o755)',
        }),
      ).toBe(false));
  });

  describe('TG02-read-outside-scope', () => {
    it('flags a read outside the declared scope', () =>
      expect(fires('TG02-read-outside-scope', { path: '/etc/passwd', operation: 'read' })).toBe(
        true,
      ));
    it('flags a get outside the declared scope', () =>
      expect(
        fires('TG02-read-outside-scope', { path: '/tmp/secrets.json', operation: 'get' }),
      ).toBe(true));
    it('flags a fetch/load outside the declared scope', () =>
      expect(
        fires('TG02-read-outside-scope', { path: '/var/data/report.csv', operation: 'fetch' }),
      ).toBe(true));
    it('does not flag a read inside the declared scope', () =>
      expect(
        fires('TG02-read-outside-scope', { path: './workspace/notes.txt', operation: 'read' }),
      ).toBe(false));
    it('does not flag a write outside scope (not a read op)', () =>
      expect(fires('TG02-read-outside-scope', { path: '/etc/passwd', operation: 'write' })).toBe(
        false,
      ));
    it('flags a read when no filesystem boundary is declared at all (empty scope means nothing is in scope)', () =>
      expect(fires('TG02-read-outside-scope', { path: '/etc/passwd', operation: 'read' }, [])).toBe(
        true,
      ));

    it("flags a read of /etc/passwd for a partial-grant agent (network: true, filesystem: [], credentials: []) -- the exact scenario TG02-read-outside-scope previously no-op'd on", () => {
      const rule = filesystemScopeRules.find((r) => r.id === 'TG02-read-outside-scope')!;
      const partialGrantCtx: RuleContext = {
        agentId: 'agent-1',
        sessionId: 'session-1',
        tool: 'fs.readFile',
        args: { path: '/etc/passwd', operation: 'read' },
        scope: { network: true, filesystem: [], credentials: [] },
      };
      const result = rule.evaluate(partialGrantCtx);
      expect(result).not.toBeNull();
      expect(['deny', 'require-approval']).toContain(result?.decision);
    });
    it('infers a read from a tool name containing "read" when no operation key is present', () => {
      const rule = filesystemScopeRules.find((r) => r.id === 'TG02-read-outside-scope')!;
      const ctxWithTool: RuleContext = {
        agentId: 'agent-1',
        sessionId: 'session-1',
        tool: 'fs.readFile',
        args: { path: '/etc/passwd' },
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
      };
      expect(rule.evaluate(ctxWithTool)).not.toBeNull();
    });
    it('flags a read-only payload embedded in a `code` argument reading outside scope', () =>
      expect(
        fires('TG02-read-outside-scope', {
          code: 'open("/etc/passwd").read()',
          operation: 'read',
        }),
      ).toBe(true));
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

    it("flags a traversal payload embedded in a code-execution tool's `code` argument", () =>
      expect(
        fires('TG02-path-traversal', {
          code: 'with open("../../etc/passwd") as f:\n    data = f.read()\n    print(data)',
        }),
      ).toBe(true));

    it('flags a Node-style traversal payload embedded in `code`', () =>
      expect(
        fires('TG02-path-traversal', {
          code: "const fs = require('fs');\nfs.readFileSync('../../../etc/shadow', 'utf8');",
        }),
      ).toBe(true));

    it('does not flag a code argument with no path-like literal at all', () =>
      expect(fires('TG02-path-traversal', { code: 'print(1 + 1)' })).toBe(false));

    it('does not flag a clean, non-traversing path embedded in code', () =>
      expect(fires('TG02-path-traversal', { code: 'open("./workspace/report.txt").read()' })).toBe(
        false,
      ));
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

    it('still fires on a double-leading-slash path targeting /etc, even when the agent is scoped to /etc itself (2026-07-13 fix -- a raw startsWith() previously missed "//etc/passwd" since it does not literally start with "/etc")', () =>
      expect(
        fires('TG02-sensitive-system-path', { path: '//etc/passwd', operation: 'write' }, ['/etc']),
      ).toBe(true));

    it('still fires on a double-leading-slash path with no filesystem scope declared at all', () =>
      expect(
        fires('TG02-sensitive-system-path', { path: '//etc/shadow', operation: 'delete' }),
      ).toBe(true));
  });

  describe('TG02 argument obfuscation resistance (2026-07-13: extended to every rule in this file, not just sensitive-system-path)', () => {
    it('TG02-sensitive-system-path still fires when a zero-width space is spliced into the path', () =>
      expect(
        fires('TG02-sensitive-system-path', { path: '/e​tc/passwd', operation: 'write' }, ['/etc']),
      ).toBe(true));

    it('TG02-write-outside-scope still fires on a path with an embedded zero-width space', () =>
      expect(
        fires('TG02-write-outside-scope', { path: '/tmp/ex​port.csv', operation: 'write' }),
      ).toBe(true));

    it('TG02-sensitive-system-path does not false-fire on a legitimately in-scope workspace path containing formatting characters', () =>
      expect(
        fires('TG02-sensitive-system-path', {
          path: './work​space/file',
          operation: 'write',
        }),
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
