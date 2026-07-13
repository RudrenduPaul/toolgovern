import { describe, expect, it, afterEach } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TraceWriter } from '../../src/trace/trace-writer.js';
import { filterTrace, parseSince, readTrace, verifyChain } from '../../src/trace/trace-reader.js';
import type { TraceEntry } from '../../src/types.js';

const tempDirs: string[] = [];

async function makeTempTraceFile(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'toolgovern-trace-reader-'));
  tempDirs.push(dir);
  return join(dir, 'trace.jsonl');
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

const emptyScope = { network: false as const, filesystem: [], credentials: [] };

describe('readTrace', () => {
  it('reads back exactly what was written, skipping blank lines', async () => {
    const filePath = await makeTempTraceFile();
    const writer = new TraceWriter(filePath);
    await writer.append({
      sessionId: 's1',
      agentId: 'a',
      tool: 'bash',
      args: {},
      decision: 'allow',
      ruleFired: [],
      declaredScope: emptyScope,
    });
    await writer.append({
      sessionId: 's1',
      agentId: 'a',
      tool: 'bash',
      args: {},
      decision: 'deny',
      ruleFired: ['TG01-rm-rf'],
      declaredScope: emptyScope,
    });

    const entries = await readTrace(filePath);
    expect(entries).toHaveLength(2);
    expect(entries[1]?.decision).toBe('deny');
  });

  it('throws a descriptive error on a malformed line', async () => {
    const filePath = await makeTempTraceFile();
    const { writeFile } = await import('node:fs/promises');
    await writeFile(filePath, '{not valid json}\n', 'utf8');
    await expect(readTrace(filePath)).rejects.toThrow(/Malformed trace line/);
  });
});

describe('parseSince', () => {
  const now = new Date('2026-07-11T12:00:00.000Z');

  it('parses minutes', () => {
    expect(parseSince('30m', now).toISOString()).toBe('2026-07-11T11:30:00.000Z');
  });
  it('parses hours', () => {
    expect(parseSince('24h', now).toISOString()).toBe('2026-07-10T12:00:00.000Z');
  });
  it('parses days', () => {
    expect(parseSince('7d', now).toISOString()).toBe('2026-07-04T12:00:00.000Z');
  });
  it('parses an ISO timestamp directly', () => {
    expect(parseSince('2026-07-01T00:00:00.000Z', now).toISOString()).toBe(
      '2026-07-01T00:00:00.000Z',
    );
  });
  it('throws on an invalid value', () => {
    expect(() => parseSince('not-a-window', now)).toThrow(/Invalid --since value/);
  });
});

describe('filterTrace', () => {
  const base: TraceEntry = {
    trace_id: 't1',
    timestamp: '2026-07-11T10:00:00.000Z',
    session_id: 's1',
    agent_id: 'coordinator',
    tool: 'bash',
    arguments_hash: 'sha256:aaa',
    decision: 'allow',
    rule_fired: [],
    declared_scope: emptyScope,
    signature: 'sha256:bbb',
    prior_trace_id: null,
  };

  const entries: TraceEntry[] = [
    base,
    {
      ...base,
      trace_id: 't2',
      agent_id: 'research-sub',
      decision: 'deny',
      rule_fired: ['TG01-rm-rf'],
    },
    {
      ...base,
      trace_id: 't3',
      timestamp: '2026-07-01T00:00:00.000Z',
      agent_id: 'research-sub',
      decision: 'require-approval',
      rule_fired: ['TG02-write-outside-scope'],
    },
  ];

  it('filters by decision', () => {
    expect(filterTrace(entries, { decision: 'deny' })).toHaveLength(1);
  });

  it('filters by agentId', () => {
    expect(filterTrace(entries, { agentId: 'research-sub' })).toHaveLength(2);
  });

  it('filters by ruleId', () => {
    expect(filterTrace(entries, { ruleId: 'TG02-write-outside-scope' })).toHaveLength(1);
  });

  it('filters by a since window, excluding older entries', () => {
    const result = filterTrace(entries, { since: '2026-07-05T00:00:00.000Z' });
    expect(result.map((e) => e.trace_id)).toEqual(['t1', 't2']);
  });

  it('combines multiple filters', () => {
    const result = filterTrace(entries, { agentId: 'research-sub', decision: 'deny' });
    expect(result.map((e) => e.trace_id)).toEqual(['t2']);
  });

  it('returns everything when no filters are given', () => {
    expect(filterTrace(entries, {})).toHaveLength(3);
  });
});

describe('verifyChain', () => {
  it('validates a chain written by TraceWriter', async () => {
    const filePath = await makeTempTraceFile();
    const writer = new TraceWriter(filePath);
    await writer.append({
      sessionId: 's1',
      agentId: 'a',
      tool: 'bash',
      args: { command: 'ls' },
      decision: 'allow',
      ruleFired: [],
      declaredScope: emptyScope,
    });
    await writer.append({
      sessionId: 's1',
      agentId: 'a',
      tool: 'bash',
      args: { command: 'pwd' },
      decision: 'allow',
      ruleFired: [],
      declaredScope: emptyScope,
    });

    const entries = await readTrace(filePath);
    const result = verifyChain(entries);
    expect(result.valid).toBe(true);
    expect(result.issues).toHaveLength(0);
  });

  it('detects a tampered signature', async () => {
    const filePath = await makeTempTraceFile();
    const writer = new TraceWriter(filePath);
    await writer.append({
      sessionId: 's1',
      agentId: 'a',
      tool: 'bash',
      args: { command: 'ls' },
      decision: 'allow',
      ruleFired: [],
      declaredScope: emptyScope,
    });
    const [entry] = await readTrace(filePath);
    const tampered: TraceEntry = { ...entry!, decision: 'deny' }; // content changed, signature stale

    const result = verifyChain([tampered]);
    expect(result.valid).toBe(false);
    expect(result.issues[0]?.reason).toMatch(/Signature does not match/);
  });

  it('rejects (does not throw on) a signature with a different length than expected -- 2026-07-13: signature comparison switched to crypto.timingSafeEqual, which throws on unequal-length buffers if not guarded', async () => {
    const filePath = await makeTempTraceFile();
    const writer = new TraceWriter(filePath);
    await writer.append({
      sessionId: 's1',
      agentId: 'a',
      tool: 'bash',
      args: { command: 'ls' },
      decision: 'allow',
      ruleFired: [],
      declaredScope: emptyScope,
    });
    const [entry] = await readTrace(filePath);
    const truncated: TraceEntry = { ...entry!, signature: entry!.signature.slice(0, -4) };

    expect(() => verifyChain([truncated])).not.toThrow();
    const result = verifyChain([truncated]);
    expect(result.valid).toBe(false);
    expect(result.issues[0]?.reason).toMatch(/Signature does not match/);
  });

  it(
    'documents the residual limitation of the unkeyed sha256 scheme: an attacker who edits an ' +
      'entry AND recomputes its signature is NOT caught, because the hash is reproducible by ' +
      'anyone -- see docs/security-model.md',
    async () => {
      const filePath = await makeTempTraceFile();
      const writer = new TraceWriter(filePath);
      await writer.append({
        sessionId: 's1',
        agentId: 'a',
        tool: 'bash',
        args: { command: 'ls' },
        decision: 'allow',
        ruleFired: [],
        declaredScope: emptyScope,
      });
      const [entry] = await readTrace(filePath);
      const tamperedContent = { ...entry!, decision: 'deny' as const };
      const { computeEntrySignature } = await import('../../src/trace/trace-writer.js');
      const forged = { ...tamperedContent, signature: computeEntrySignature(tamperedContent) };

      const result = verifyChain([forged]);
      // This is the documented v0.1 limitation, not a passing "security" assertion: without a
      // secret key, anyone with write access to the trace file can recompute a valid signature
      // after tampering. The fix is `TraceWriter`'s optional `secretKey` (hmac-sha256 signing) --
      // see the 'hmac-sha256 keyed signing' tests below for the same scenario WITH a key, where
      // the forgery is caught.
      expect(result.valid).toBe(true);
    },
  );

  describe('hmac-sha256 keyed signing', () => {
    const secretKey = Buffer.from('test-only-secret-key-do-not-use-in-real-deployments');

    it('verifies a chain written with a secret key when the same key is supplied', async () => {
      const filePath = await makeTempTraceFile();
      const writer = new TraceWriter(filePath, { secretKey });
      await writer.append({
        sessionId: 's1',
        agentId: 'a',
        tool: 'bash',
        args: { command: 'ls' },
        decision: 'allow',
        ruleFired: [],
        declaredScope: emptyScope,
      });
      const entries = await readTrace(filePath);
      expect(entries[0]?.signature.startsWith('hmac-sha256:')).toBe(true);
      const result = verifyChain(entries, { secretKey });
      expect(result.valid).toBe(true);
    });

    it('verifies a chain written WITHOUT a key even when the caller supplies a secretKey anyway (regression: a key should never be applied to a sha256:-scheme entry)', async () => {
      const filePath = await makeTempTraceFile();
      const writer = new TraceWriter(filePath); // no secretKey -- default unkeyed sha256 scheme
      await writer.append({
        sessionId: 's1',
        agentId: 'a',
        tool: 'bash',
        args: { command: 'ls' },
        decision: 'allow',
        ruleFired: [],
        declaredScope: emptyScope,
      });
      const entries = await readTrace(filePath);
      expect(entries[0]?.signature.startsWith('sha256:')).toBe(true);
      // Passing a secretKey here must not matter -- before the fix, verifyChain always applied
      // whatever key it was given regardless of the entry's own scheme, which meant every
      // legitimate unkeyed entry spuriously failed to verify the moment a caller (e.g. the CLI's
      // --key-file flag) supplied any key at all.
      const result = verifyChain(entries, { secretKey });
      expect(result.valid).toBe(true);
    });

    it('reports an issue (does not silently pass) when no key is supplied to verify an hmac-signed entry', async () => {
      const filePath = await makeTempTraceFile();
      const writer = new TraceWriter(filePath, { secretKey });
      await writer.append({
        sessionId: 's1',
        agentId: 'a',
        tool: 'bash',
        args: { command: 'ls' },
        decision: 'allow',
        ruleFired: [],
        declaredScope: emptyScope,
      });
      const entries = await readTrace(filePath);
      const result = verifyChain(entries);
      expect(result.valid).toBe(false);
      expect(result.issues[0]?.reason).toMatch(/no secretKey was supplied/);
    });

    it('catches tampering that the unkeyed scheme would miss: an attacker without the key cannot forge a valid hmac signature', async () => {
      const filePath = await makeTempTraceFile();
      const writer = new TraceWriter(filePath, { secretKey });
      await writer.append({
        sessionId: 's1',
        agentId: 'a',
        tool: 'bash',
        args: { command: 'ls' },
        decision: 'allow',
        ruleFired: [],
        declaredScope: emptyScope,
      });
      const [entry] = await readTrace(filePath);
      const tamperedContent = { ...entry!, decision: 'deny' as const };
      const { computeEntrySignature } = await import('../../src/trace/trace-writer.js');
      // The attacker doesn't have the real secret key, so they sign with a guessed/wrong one.
      const forged = {
        ...tamperedContent,
        signature: computeEntrySignature(tamperedContent, Buffer.from('wrong-key')),
      };

      const result = verifyChain([forged], { secretKey });
      expect(result.valid).toBe(false);
      expect(result.issues[0]?.reason).toMatch(/Signature does not match/);
    });

    it('rejects an entry with an unrecognized signature scheme', () => {
      const entry: TraceEntry = {
        trace_id: 't1',
        timestamp: '2026-07-11T10:00:00.000Z',
        session_id: 's1',
        agent_id: 'a',
        tool: 'bash',
        arguments_hash: 'sha256:aaa',
        decision: 'allow',
        rule_fired: [],
        declared_scope: emptyScope,
        signature: 'md5:deadbeef',
        prior_trace_id: null,
      };
      const result = verifyChain([entry]);
      expect(result.valid).toBe(false);
      expect(result.issues[0]?.reason).toMatch(/Unrecognized signature scheme/);
    });
  });

  it('detects a broken prior_trace_id chain', async () => {
    const filePath = await makeTempTraceFile();
    const writer = new TraceWriter(filePath);
    await writer.append({
      sessionId: 's1',
      agentId: 'a',
      tool: 'bash',
      args: {},
      decision: 'allow',
      ruleFired: [],
      declaredScope: emptyScope,
    });
    await writer.append({
      sessionId: 's1',
      agentId: 'a',
      tool: 'bash',
      args: {},
      decision: 'allow',
      ruleFired: [],
      declaredScope: emptyScope,
    });

    const entries = await readTrace(filePath);
    // Simulate a deleted middle entry -- second entry now looks like it has no valid predecessor.
    const brokenChain = [entries[1]!];
    const result = verifyChain(brokenChain);
    expect(result.valid).toBe(false);
    expect(result.issues.some((i) => i.reason.includes('prior_trace_id'))).toBe(true);
  });
});
