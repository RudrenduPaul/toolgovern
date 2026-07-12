import { describe, expect, it, afterEach } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TraceWriter } from 'toolgovern';
import { auditCommand, parseArgs, runCommand, validateCommand } from '../src/cli.js';

const tempDirs: string[] = [];
afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});
async function tempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'toolgovern-cli-'));
  tempDirs.push(dir);
  return dir;
}

describe('parseArgs', () => {
  it('separates positional arguments from flags', () => {
    const result = parseArgs(['./trace.jsonl', '--since', '24h', '--decision', 'deny']);
    expect(result.positional).toEqual(['./trace.jsonl']);
    expect(result.flags).toEqual({ since: '24h', decision: 'deny' });
  });

  it('treats a flag with no value as a boolean true', () => {
    const result = parseArgs(['./trace.jsonl', '--verify-chain']);
    expect(result.flags['verify-chain']).toBe(true);
  });

  it('treats a flag immediately followed by another flag as boolean', () => {
    const result = parseArgs(['--verify-chain', '--since', '1h']);
    expect(result.flags['verify-chain']).toBe(true);
    expect(result.flags.since).toBe('1h');
  });
});

describe('validateCommand', () => {
  it('returns code 0 for a valid policy file', async () => {
    const dir = await tempDir();
    const filePath = join(dir, 'policy.yml');
    await writeFile(
      filePath,
      [
        'name: strict-shell',
        'scope:',
        '  network: false',
        '  filesystem: []',
        '  credentials: []',
      ].join('\n'),
      'utf8',
    );
    const result = validateCommand(filePath);
    expect(result.code).toBe(0);
    expect(result.stdout).toMatch(/OK/);
  });

  it('returns code 1 and lists errors for an invalid policy file', async () => {
    const dir = await tempDir();
    const filePath = join(dir, 'policy.yml');
    await writeFile(filePath, 'name: broken\n', 'utf8');
    const result = validateCommand(filePath);
    expect(result.code).toBe(1);
    expect(result.stderr).toMatch(/INVALID/);
  });

  it('returns code 2 when no policy file argument is given', () => {
    const result = validateCommand(undefined);
    expect(result.code).toBe(2);
  });

  it('returns code 1 for a file that does not exist', () => {
    const result = validateCommand('/nonexistent/policy.yml');
    expect(result.code).toBe(1);
    expect(result.stderr).toMatch(/Failed to read\/parse/);
  });
});

describe('auditCommand', () => {
  async function writeTraceFile(dir: string): Promise<string> {
    const filePath = join(dir, 'trace.jsonl');
    const lines = [
      JSON.stringify({
        trace_id: 't1',
        timestamp: '2026-07-11T10:00:00.000Z',
        session_id: 's1',
        agent_id: 'coordinator',
        tool: 'bash',
        arguments_hash: 'sha256:aaa',
        decision: 'allow',
        rule_fired: [],
        declared_scope: { network: false, filesystem: [], credentials: [] },
        signature: 'sha256:bbb',
        prior_trace_id: null,
      }),
      JSON.stringify({
        trace_id: 't2',
        timestamp: '2026-07-11T10:05:00.000Z',
        session_id: 's1',
        agent_id: 'research-sub',
        tool: 'bash',
        arguments_hash: 'sha256:ccc',
        decision: 'deny',
        rule_fired: ['TG01-pipe-to-shell'],
        declared_scope: { network: false, filesystem: [], credentials: [] },
        signature: 'sha256:ddd',
        prior_trace_id: 't1',
      }),
    ];
    await writeFile(filePath, `${lines.join('\n')}\n`, 'utf8');
    return filePath;
  }

  it('filters by decision', async () => {
    const dir = await tempDir();
    const filePath = await writeTraceFile(dir);
    const result = await auditCommand(filePath, { decision: 'deny' });
    expect(result.code).toBe(0);
    expect(result.stdout).toMatch(/DENY/);
    expect(result.stdout).toMatch(/1 of 2 trace entries matched/);
  });

  it('returns everything with no flags', async () => {
    const dir = await tempDir();
    const filePath = await writeTraceFile(dir);
    const result = await auditCommand(filePath, {});
    expect(result.stdout).toMatch(/2 of 2 trace entries matched/);
  });

  it('returns code 2 for an invalid --decision value', async () => {
    const dir = await tempDir();
    const filePath = await writeTraceFile(dir);
    const result = await auditCommand(filePath, { decision: 'maybe' });
    expect(result.code).toBe(2);
  });

  it('returns code 1 for a missing trace file', async () => {
    const result = await auditCommand('/nonexistent/trace.jsonl', {});
    expect(result.code).toBe(1);
  });

  it('returns a clean code-2 error (not a raw stack trace) for an unsupported --since unit', async () => {
    const dir = await tempDir();
    const filePath = await writeTraceFile(dir);
    const result = await auditCommand(filePath, { since: '1s' });
    expect(result.code).toBe(2);
    expect(result.stderr).toMatch(/Invalid --since value "1s"/);
    expect(result.stderr).not.toMatch(/at parseSince|at filterTrace|\.js:\d+:\d+/);
  });

  it('returns code 2 when no trace file argument is given', async () => {
    const result = await auditCommand(undefined, {});
    expect(result.code).toBe(2);
  });

  it('reports chain verification success with --verify-chain', async () => {
    const dir = await tempDir();
    const filePath = await writeTraceFile(dir);
    const result = await auditCommand(filePath, { 'verify-chain': true });
    // The fixture's signature/prior_trace_id values are synthetic (not produced by
    // TraceWriter), so chain verification is expected to fail here -- this test just proves
    // the flag is wired up and reports a structured failure rather than crashing.
    expect(result.code).toBe(1);
    expect(result.stderr).toMatch(/CHAIN INVALID/);
  });

  it('verifies an unkeyed (sha256) trace fine even when --key-file is passed anyway (regression)', async () => {
    const dir = await tempDir();
    const traceFilePath = join(dir, 'trace.jsonl');
    const keyFilePath = join(dir, 'trace-key.bin');
    await writeFile(keyFilePath, 'some-key-that-was-never-used-to-sign-anything', 'utf8');

    const writer = new TraceWriter(traceFilePath); // default unkeyed sha256 scheme
    await writer.append({
      sessionId: 's1',
      agentId: 'coordinator',
      tool: 'bash',
      args: { command: 'ls' },
      decision: 'allow',
      ruleFired: [],
      declaredScope: { network: false, filesystem: [], credentials: [] },
    });

    // Before the fix, supplying --key-file for a trace that was never hmac-signed made every
    // entry spuriously fail chain verification, because the key was applied regardless of the
    // entry's own signature scheme.
    const result = await auditCommand(traceFilePath, {
      'verify-chain': true,
      'key-file': keyFilePath,
    });
    expect(result.code).toBe(0);
    expect(result.stdout).toMatch(/Chain OK/);
  });

  it('verifies an hmac-signed trace when --key-file points at the matching key', async () => {
    const dir = await tempDir();
    const traceFilePath = join(dir, 'trace.jsonl');
    const keyFilePath = join(dir, 'trace-key.bin');
    await writeFile(keyFilePath, 'a-test-secret-key', 'utf8');
    const secretKey = await (await import('node:fs/promises')).readFile(keyFilePath);

    const writer = new TraceWriter(traceFilePath, { secretKey });
    await writer.append({
      sessionId: 's1',
      agentId: 'coordinator',
      tool: 'bash',
      args: { command: 'ls' },
      decision: 'allow',
      ruleFired: [],
      declaredScope: { network: false, filesystem: [], credentials: [] },
    });

    const result = await auditCommand(traceFilePath, {
      'verify-chain': true,
      'key-file': keyFilePath,
    });
    expect(result.code).toBe(0);
    expect(result.stdout).toMatch(/Chain OK/);
  });

  it('reports a chain failure (not a crash) when --key-file is missing for an hmac-signed trace', async () => {
    const dir = await tempDir();
    const traceFilePath = join(dir, 'trace.jsonl');
    const writer = new TraceWriter(traceFilePath, { secretKey: Buffer.from('some-key') });
    await writer.append({
      sessionId: 's1',
      agentId: 'coordinator',
      tool: 'bash',
      args: { command: 'ls' },
      decision: 'allow',
      ruleFired: [],
      declaredScope: { network: false, filesystem: [], credentials: [] },
    });

    const result = await auditCommand(traceFilePath, { 'verify-chain': true });
    expect(result.code).toBe(1);
    expect(result.stderr).toMatch(/no secretKey was supplied/);
  });

  it('returns code 1 with a clear message when --key-file itself does not exist', async () => {
    const dir = await tempDir();
    const filePath = await writeTraceFile(dir);
    const result = await auditCommand(filePath, {
      'verify-chain': true,
      'key-file': '/nonexistent/trace-key.bin',
    });
    expect(result.code).toBe(1);
    expect(result.stderr).toMatch(/Failed to read --key-file/);
  });
});

describe('runCommand', () => {
  it('dispatches to validate', async () => {
    const dir = await tempDir();
    const filePath = join(dir, 'policy.yml');
    await writeFile(
      filePath,
      ['name: x', 'scope:', '  network: false', '  filesystem: []', '  credentials: []'].join('\n'),
      'utf8',
    );
    const result = await runCommand(['validate', filePath]);
    expect(result.code).toBe(0);
  });

  it('dispatches to audit', async () => {
    const dir = await tempDir();
    const filePath = join(dir, 'trace.jsonl');
    await writeFile(filePath, '', 'utf8');
    const result = await runCommand(['audit', filePath]);
    expect(result.code).toBe(0);
  });

  it('prints usage for an unknown command', async () => {
    const result = await runCommand(['bogus']);
    expect(result.code).toBe(2);
    expect(result.stderr).toMatch(/Unknown command/);
  });

  it('prints usage for --help', async () => {
    const result = await runCommand(['--help']);
    expect(result.code).toBe(0);
    expect(result.stdout).toMatch(/Usage/);
  });

  it('prints usage and exits 2 for no command at all', async () => {
    const result = await runCommand([]);
    expect(result.code).toBe(2);
  });
});
