import { describe, expect, it, afterEach } from 'vitest';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  governTool,
  resumePendingApproval,
  InvalidAgentIdError,
  PendingApprovalNotResolvableError,
  ToolGovernDenialError,
} from '../../src/middleware/onToolCall.js';
import type { ToolDefinition } from '../../src/middleware/onToolCall.js';
import { PendingApprovalRegistry } from '../../src/approval/pending-registry.js';
import { ScopeRegistry } from '../../src/scoping/inheritance-enforcer.js';
import { TraceWriter } from '../../src/trace/trace-writer.js';

const tempDirs: string[] = [];
afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});
async function makeTempTraceFile(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'toolgovern-middleware-'));
  tempDirs.push(dir);
  return join(dir, 'trace.jsonl');
}

function makeShellTool(): ToolDefinition<{ command: string }, { ran: string }> {
  return {
    name: 'bash',
    execute: (args) => ({ ran: args.command }),
  };
}

describe('governTool', () => {
  it('allows a clean call through to the wrapped tool', async () => {
    const gated = governTool(makeShellTool(), {
      scope: { network: false, filesystem: ['./workspace'], credentials: [] },
    });
    const result = await gated.execute({ command: 'ls ./workspace' });
    expect(result).toEqual({ ran: 'ls ./workspace' });
  });

  it('denies a high-risk call and never executes the wrapped tool', async () => {
    let executed = false;
    const tool: ToolDefinition<{ command: string }, unknown> = {
      name: 'bash',
      execute: (args) => {
        executed = true;
        return { ran: args.command };
      },
    };
    const gated = governTool(tool, {
      scope: { network: false, filesystem: ['./workspace'], credentials: [] },
    });

    await expect(gated.execute({ command: 'rm -rf /' })).rejects.toThrow(ToolGovernDenialError);
    expect(executed).toBe(false);
  });

  it('a ToolGovernDenialError carries the fired rule IDs', async () => {
    const gated = governTool(makeShellTool(), {
      scope: { network: false, filesystem: ['./workspace'], credentials: [] },
    });
    try {
      await gated.execute({ command: 'rm -rf /' });
      expect.unreachable('expected governTool to throw');
    } catch (error) {
      expect(error).toBeInstanceOf(ToolGovernDenialError);
      const denial = error as ToolGovernDenialError;
      expect(denial.decisionInfo.firedRules.map((r) => r.ruleId)).toContain('TG01-rm-rf');
    }
  });

  describe('require-approval', () => {
    it('executes the tool when the approval handler approves', async () => {
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        onApprovalRequired: () => true,
      });
      const result = await gated.execute({ command: 'sudo apt-get update' });
      expect(result).toEqual({ ran: 'sudo apt-get update' });
    });

    it('denies the call when the approval handler rejects', async () => {
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        onApprovalRequired: () => false,
      });
      await expect(gated.execute({ command: 'sudo apt-get update' })).rejects.toThrow(
        ToolGovernDenialError,
      );
    });

    it('fails closed (denies) when no approval handler is provided', async () => {
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
      });
      await expect(gated.execute({ command: 'sudo apt-get update' })).rejects.toThrow(
        ToolGovernDenialError,
      );
    });

    it('fails closed when the approval handler does not resolve before the timeout', async () => {
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        onApprovalRequired: () => new Promise(() => {}), // never resolves
        approvalTimeoutMs: 20,
      });
      await expect(gated.execute({ command: 'sudo apt-get update' })).rejects.toThrow(
        ToolGovernDenialError,
      );
    });

    it('fails closed, as a proper ToolGovernDenialError, when the handler throws synchronously', async () => {
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        onApprovalRequired: () => {
          throw new Error('handler blew up');
        },
      });
      await expect(gated.execute({ command: 'sudo apt-get update' })).rejects.toThrow(
        ToolGovernDenialError,
      );
    });

    it('fails closed when the handler returns a rejected promise', async () => {
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        onApprovalRequired: () => Promise.reject(new Error('async handler blew up')),
      });
      await expect(gated.execute({ command: 'sudo apt-get update' })).rejects.toThrow(
        ToolGovernDenialError,
      );
    });

    it('still writes a trace entry when the approval handler throws (no silent audit gap)', async () => {
      const filePath = await makeTempTraceFile();
      const trace = new TraceWriter(filePath);
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        trace,
        onApprovalRequired: () => {
          throw new Error('handler blew up');
        },
      });
      await expect(gated.execute({ command: 'sudo apt-get update' })).rejects.toThrow(
        ToolGovernDenialError,
      );
      const raw = await readFile(filePath, 'utf8');
      const [entry] = raw
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line));
      // The point of this test is narrower than what decision gets recorded: the entry exists at
      // all. Before the fix for "no silent audit gap", a throwing handler skipped this
      // trace.append() call entirely. A throwing handler fails closed (see the "fails closed"
      // test above), so the recorded decision is the final outcome -- `deny` -- not the
      // classifier's original `require-approval` verdict; that distinction is covered by the
      // "records the final human decision" tests below.
      expect(entry.decision).toBe('deny');
      expect(entry.rule_fired).toContain('TG01-sudo');
    });

    it("records the final decision (allow) in the trace after a human approves, not the classifier's original require-approval decision", async () => {
      const filePath = await makeTempTraceFile();
      const trace = new TraceWriter(filePath);
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        trace,
        onApprovalRequired: () => true,
      });

      const result = await gated.execute({ command: 'sudo apt-get update' });
      expect(result).toEqual({ ran: 'sudo apt-get update' });

      const raw = await readFile(filePath, 'utf8');
      const [entry] = raw
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line));
      // The classifier's own verdict for this call is `require-approval` -- the trace must record
      // what the human actually decided (`allow`), not that pre-approval verdict.
      expect(entry.decision).toBe('allow');
      expect(entry.rule_fired).toContain('TG01-sudo');
    });

    it("records the final decision (deny) in the trace after a human denies, not the classifier's original require-approval decision", async () => {
      const filePath = await makeTempTraceFile();
      const trace = new TraceWriter(filePath);
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        trace,
        onApprovalRequired: () => false,
      });

      await expect(gated.execute({ command: 'sudo apt-get update' })).rejects.toThrow(
        ToolGovernDenialError,
      );

      const raw = await readFile(filePath, 'utf8');
      const [entry] = raw
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line));
      // A denied approval must not be indistinguishable from an approved one in the trace -- both
      // start from the same `require-approval` classifier verdict, so the recorded `decision` is
      // the only thing that lets an auditor tell them apart.
      expect(entry.decision).toBe('deny');
      expect(entry.rule_fired).toContain('TG01-sudo');
    });

    it('records approvedBy on the trace entry when the approval handler supplies a human identity', async () => {
      const filePath = await makeTempTraceFile();
      const trace = new TraceWriter(filePath);
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        trace,
        onApprovalRequired: () => ({ approved: true, approvedBy: 'alice@example.com' }),
      });

      await gated.execute({ command: 'sudo apt-get update' });

      const raw = await readFile(filePath, 'utf8');
      const [entry] = raw
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line));
      expect(entry.decision).toBe('allow');
      expect(entry.approved_by).toBe('alice@example.com');
    });

    it('supports an async approval handler', async () => {
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        onApprovalRequired: async () => {
          await new Promise((resolve) => setTimeout(resolve, 5));
          return true;
        },
      });
      const result = await gated.execute({ command: 'sudo apt-get update' });
      expect(result).toEqual({ ran: 'sudo apt-get update' });
    });
  });

  describe('defaultDecision', () => {
    it('overrides a clean call to deny when defaultDecision is deny', async () => {
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        defaultDecision: 'deny',
      });
      await expect(gated.execute({ command: 'ls ./workspace' })).rejects.toThrow(
        ToolGovernDenialError,
      );
    });

    it('does not override an explicit rule verdict', async () => {
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        defaultDecision: 'deny',
        onApprovalRequired: () => true,
      });
      // sudo fires TG01-sudo (require-approval); defaultDecision must not force it to plain deny.
      const result = await gated.execute({ command: 'sudo apt-get update' });
      expect(result).toEqual({ ran: 'sudo apt-get update' });
    });
  });

  describe('scope registry integration', () => {
    it('registers a root agent and grants it its own declared scope', async () => {
      const registry = new ScopeRegistry();
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        agentId: 'coordinator',
        sessionId: 's1',
        scopeRegistry: registry,
      });
      await gated.execute({ command: 'ls ./workspace' });
      expect(registry.getEffectiveScope('coordinator')).toEqual({
        network: false,
        filesystem: ['./workspace'],
        credentials: [],
      });
    });

    it('a sub-agent is capped to the intersection with its coordinator', async () => {
      const registry = new ScopeRegistry();
      registry.registerRootAgent('coordinator', 's1', {
        network: false,
        filesystem: ['./workspace'],
        credentials: [],
      });
      const gated = governTool(makeShellTool(), {
        scope: { network: true, filesystem: ['./workspace', '/'], credentials: ['anything'] },
        agentId: 'research-sub',
        sessionId: 's1',
        coordinatorId: 'coordinator',
        scopeRegistry: registry,
      });
      await gated.execute({ command: 'ls ./workspace' });
      expect(registry.getEffectiveScope('research-sub')).toEqual({
        network: false,
        filesystem: ['./workspace'],
        credentials: [],
      });
    });

    it('denies a sub-agent call for a credential its coordinator never had (TG04 + TG05)', async () => {
      const registry = new ScopeRegistry();
      registry.registerRootAgent('coordinator', 's1', {
        network: false,
        filesystem: ['./workspace'],
        credentials: [],
      });
      const readTool: ToolDefinition<{ path: string }, unknown> = {
        name: 'fs.read',
        execute: () => ({ contents: 'secret' }),
      };
      const gated = governTool(readTool, {
        scope: { network: false, filesystem: [], credentials: ['.aws/credentials'] },
        agentId: 'research-sub',
        sessionId: 's1',
        coordinatorId: 'coordinator',
        scopeRegistry: registry,
      });

      try {
        await gated.execute({ path: '.aws/credentials' });
        expect.unreachable('expected denial');
      } catch (error) {
        const denial = error as ToolGovernDenialError;
        const ruleIds = denial.decisionInfo.firedRules.map((r) => r.ruleId);
        expect(ruleIds).toContain('TG04-cloud-credential-file');
        expect(ruleIds).toContain('TG05-credential-exceeds-grant');
      }
    });
  });

  describe('trace integration', () => {
    it('writes one trace entry per call with the decision and fired rule IDs', async () => {
      const filePath = await makeTempTraceFile();
      const trace = new TraceWriter(filePath);
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        agentId: 'coordinator',
        sessionId: 's1',
        trace,
      });

      await gated.execute({ command: 'ls ./workspace' });
      await expect(gated.execute({ command: 'rm -rf /' })).rejects.toThrow();

      const raw = await readFile(filePath, 'utf8');
      const lines = raw
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line));
      expect(lines).toHaveLength(2);
      expect(lines[0].decision).toBe('allow');
      expect(lines[1].decision).toBe('deny');
      expect(lines[1].rule_fired).toContain('TG01-rm-rf');
      expect(lines[1].prior_trace_id).toBe(lines[0].trace_id);
    });

    it('records a synthetic rule_fired marker when a defaultDecision override denies a clean call', async () => {
      const filePath = await makeTempTraceFile();
      const trace = new TraceWriter(filePath);
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        agentId: 'coordinator',
        sessionId: 's1',
        trace,
        defaultDecision: 'deny',
      });

      await expect(gated.execute({ command: 'ls ./workspace' })).rejects.toThrow();
      const raw = await readFile(filePath, 'utf8');
      const [entry] = raw
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line));
      expect(entry.decision).toBe('deny');
      expect(entry.rule_fired).toEqual(['policy-default-decision']);
    });
  });

  describe('rule overrides', () => {
    it('rules.disable suppresses a specific rule', async () => {
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        rules: { disable: ['TG01-rm-rf'] },
      });
      const result = await gated.execute({ command: 'rm -rf /' });
      expect(result).toEqual({ ran: 'rm -rf /' });
    });

    it('rules.requireApproval downgrades a deny to an approval gate', async () => {
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        rules: { requireApproval: ['TG01-rm-rf'] },
        onApprovalRequired: () => true,
      });
      const result = await gated.execute({ command: 'rm -rf /' });
      expect(result).toEqual({ ran: 'rm -rf /' });
    });
  });

  it('onDecision fires for every call with the resolved gate info', async () => {
    const seen: string[] = [];
    const gated = governTool(makeShellTool(), {
      scope: { network: false, filesystem: ['./workspace'], credentials: [] },
      onDecision: (info) => seen.push(info.decision),
    });
    await gated.execute({ command: 'ls ./workspace' });
    await expect(gated.execute({ command: 'rm -rf /' })).rejects.toThrow();
    expect(seen).toEqual(['allow', 'deny']);
  });

  describe('onToolResult', () => {
    function makeThrowingTool(message: string): ToolDefinition<{ command: string }, unknown> {
      return {
        name: 'bash',
        execute: () => {
          throw new Error(message);
        },
      };
    }

    it('catches an error thrown inside tool.execute() instead of it propagating unguarded', async () => {
      const filePath = await makeTempTraceFile();
      const trace = new TraceWriter(filePath);
      const gated = governTool(makeThrowingTool('/Users/secret/leaked-path failure'), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        agentId: 'coordinator',
        sessionId: 's1',
        trace,
      });

      // With no onToolResult, the caught error still rethrows (pass-through), but it must be a
      // clean rejection -- not an unhandled exception -- and the gate's own trace entry (written
      // before execute() ever ran) must be well-formed.
      await expect(gated.execute({ command: 'ls ./workspace' })).rejects.toThrow(
        '/Users/secret/leaked-path failure',
      );

      const raw = await readFile(filePath, 'utf8');
      const [entry] = raw
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line));
      expect(entry.decision).toBe('allow');
      expect(entry.tool).toBe('bash');
    });

    it('lets onToolResult redact a thrown error before it reaches the caller', async () => {
      const gated = governTool(makeThrowingTool('leaked secret: sk-12345'), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        onToolResult: (result) => {
          if (result instanceof Error) {
            return { error: 'redacted' };
          }
          return result;
        },
      });

      const result = await gated.execute({ command: 'ls ./workspace' });
      expect(result).toEqual({ error: 'redacted' });
    });

    it('lets onToolResult transform/redact a successful result before it reaches the caller', async () => {
      const tool: ToolDefinition<{ command: string }, { ran: string; secret: string }> = {
        name: 'bash',
        execute: (args) => ({ ran: args.command, secret: 'sk-abc123' }),
      };
      const gated = governTool(tool, {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        onToolResult: (result) => {
          const { secret: _secret, ...rest } = result as { ran: string; secret: string };
          return { ...rest, secret: '[REDACTED]' };
        },
      });

      const result = await gated.execute({ command: 'ls ./workspace' });
      expect(result).toEqual({ ran: 'ls ./workspace', secret: '[REDACTED]' });
    });

    it('receives the RuleContext as its second argument', async () => {
      let seenCtx: unknown;
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        agentId: 'coordinator',
        sessionId: 's1',
        onToolResult: (result, ctx) => {
          seenCtx = ctx;
          return result;
        },
      });
      await gated.execute({ command: 'ls ./workspace' });
      expect(seenCtx).toMatchObject({
        agentId: 'coordinator',
        sessionId: 's1',
        tool: 'bash',
      });
    });

    it('without onToolResult, a successful result passes through unchanged (existing behavior)', async () => {
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
      });
      const result = await gated.execute({ command: 'ls ./workspace' });
      expect(result).toEqual({ ran: 'ls ./workspace' });
    });
  });

  // These tests cover a PARTIAL fix: format validation and identity-source provenance tracking,
  // not cryptographic identity verification. `agentId` remains a caller-asserted string; a
  // well-formed lie still passes. See docs/security-model.md, "Agent identity is caller-asserted,
  // not cryptographically verified."
  describe('agent identity format validation', () => {
    it('rejects an empty explicit agentId at wrap time', () => {
      expect(() =>
        governTool(makeShellTool(), {
          scope: { network: false, filesystem: ['./workspace'], credentials: [] },
          agentId: '',
        }),
      ).toThrow(InvalidAgentIdError);
    });

    it('rejects an explicit agentId containing a null byte', () => {
      expect(() =>
        governTool(makeShellTool(), {
          scope: { network: false, filesystem: ['./workspace'], credentials: [] },
          agentId: 'agent\u0000-evil',
        }),
      ).toThrow(InvalidAgentIdError);
    });

    it('rejects an explicit agentId containing an embedded newline', () => {
      expect(() =>
        governTool(makeShellTool(), {
          scope: { network: false, filesystem: ['./workspace'], credentials: [] },
          agentId: 'agent\nfake_trace_line',
        }),
      ).toThrow(InvalidAgentIdError);
    });

    it('rejects an explicit agentId past the length ceiling', () => {
      expect(() =>
        governTool(makeShellTool(), {
          scope: { network: false, filesystem: ['./workspace'], credentials: [] },
          agentId: 'a'.repeat(257),
        }),
      ).toThrow(InvalidAgentIdError);
    });

    it('never executes the wrapped tool when agentId is malformed', async () => {
      let executed = false;
      const tool: ToolDefinition<{ command: string }, unknown> = {
        name: 'bash',
        execute: (args) => {
          executed = true;
          return { ran: args.command };
        },
      };
      expect(() =>
        governTool(tool, {
          scope: { network: false, filesystem: ['./workspace'], credentials: [] },
          agentId: '',
        }),
      ).toThrow(InvalidAgentIdError);
      expect(executed).toBe(false);
    });

    it('accepts a well-formed explicit agentId and behaves like any other call (no regression)', async () => {
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        agentId: 'coordinator',
      });
      const result = await gated.execute({ command: 'ls ./workspace' });
      expect(result).toEqual({ ran: 'ls ./workspace' });
    });

    it('the default fallback agentId is unaffected when no agentId is supplied (no regression)', async () => {
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
      });
      const result = await gated.execute({ command: 'ls ./workspace' });
      expect(result).toEqual({ ran: 'ls ./workspace' });
    });
  });

  describe('agent identity source (trace provenance, not verification)', () => {
    it('records agent_id_source "explicit" when the caller supplies agentId', async () => {
      const filePath = await makeTempTraceFile();
      const trace = new TraceWriter(filePath);
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        agentId: 'coordinator',
        trace,
      });
      await gated.execute({ command: 'ls ./workspace' });

      const raw = await readFile(filePath, 'utf8');
      const [entry] = raw
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line));
      expect(entry.agent_id).toBe('coordinator');
      expect(entry.agent_id_source).toBe('explicit');
    });

    it('records agent_id_source "fallback" when no agentId is supplied', async () => {
      const filePath = await makeTempTraceFile();
      const trace = new TraceWriter(filePath);
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        trace,
      });
      await gated.execute({ command: 'ls ./workspace' });

      const raw = await readFile(filePath, 'utf8');
      const [entry] = raw
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line));
      expect(entry.agent_id).toBe('default-agent');
      expect(entry.agent_id_source).toBe('fallback');
    });

    it('distinguishes explicit from fallback across two different gated tools sharing one trace', async () => {
      const filePath = await makeTempTraceFile();
      const trace = new TraceWriter(filePath);
      const explicitGated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        agentId: 'research-sub',
        sessionId: 's1',
        trace,
      });
      const fallbackGated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        sessionId: 's1',
        trace,
      });

      await explicitGated.execute({ command: 'ls ./workspace' });
      await fallbackGated.execute({ command: 'ls ./workspace' });

      const raw = await readFile(filePath, 'utf8');
      const [first, second] = raw
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line));
      expect(first.agent_id_source).toBe('explicit');
      expect(second.agent_id_source).toBe('fallback');
    });
  });

  describe('idempotency', () => {
    // Counts real executions so tests can assert the underlying tool only actually ran once
    // for a deduped retry, rather than just asserting on the returned value.
    function makeCountingTool(): {
      tool: ToolDefinition<{ amount: number; to: string }, { chargeId: number }>;
      calls: () => number;
    } {
      let calls = 0;
      const tool: ToolDefinition<{ amount: number; to: string }, { chargeId: number }> = {
        name: 'charge-card',
        execute: () => {
          calls += 1;
          return { chargeId: calls };
        },
      };
      return { tool, calls: () => calls };
    }

    it('returns the cached result for an identical retry within the TTL window, executing the tool only once', async () => {
      const { tool, calls } = makeCountingTool();
      const gated = governTool(tool, {
        scope: { network: false, filesystem: [], credentials: [] },
        idempotency: { enabled: true, ttlMs: 5_000 },
      });

      const first = await gated.execute({ amount: 100, to: 'acct-1' });
      const second = await gated.execute({ amount: 100, to: 'acct-1' });

      expect(first).toEqual({ chargeId: 1 });
      expect(second).toEqual({ chargeId: 1 });
      expect(calls()).toBe(1);
    });

    it('treats argument key order as irrelevant to the idempotency key (stable serialization)', async () => {
      const { tool, calls } = makeCountingTool();
      const gated = governTool(tool, {
        scope: { network: false, filesystem: [], credentials: [] },
        idempotency: { enabled: true, ttlMs: 5_000 },
      });

      await gated.execute({ amount: 100, to: 'acct-1' });
      // Same logical call, arguments supplied in a different key order -- must still hit cache.
      const second = await gated.execute({ to: 'acct-1', amount: 100 });

      expect(second).toEqual({ chargeId: 1 });
      expect(calls()).toBe(1);
    });

    it('does not cache across different arguments -- each distinct call still executes', async () => {
      const { tool, calls } = makeCountingTool();
      const gated = governTool(tool, {
        scope: { network: false, filesystem: [], credentials: [] },
        idempotency: { enabled: true, ttlMs: 5_000 },
      });

      await gated.execute({ amount: 100, to: 'acct-1' });
      await gated.execute({ amount: 200, to: 'acct-1' });

      expect(calls()).toBe(2);
    });

    it('executes again once the cached entry has expired past its TTL', async () => {
      const { tool, calls } = makeCountingTool();
      const gated = governTool(tool, {
        scope: { network: false, filesystem: [], credentials: [] },
        idempotency: { enabled: true, ttlMs: 20 },
      });

      const first = await gated.execute({ amount: 100, to: 'acct-1' });
      await new Promise((resolve) => setTimeout(resolve, 60));
      const second = await gated.execute({ amount: 100, to: 'acct-1' });

      expect(first).toEqual({ chargeId: 1 });
      expect(second).toEqual({ chargeId: 2 });
      expect(calls()).toBe(2);
    });

    it('does not cache a denied call -- a retry is re-classified, not replayed', async () => {
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        idempotency: { enabled: true, ttlMs: 5_000 },
      });

      await expect(gated.execute({ command: 'rm -rf /' })).rejects.toThrow(ToolGovernDenialError);
      await expect(gated.execute({ command: 'rm -rf /' })).rejects.toThrow(ToolGovernDenialError);
    });

    it('with idempotency not enabled (default), every call executes independently -- no caching, no regression', async () => {
      const { tool, calls } = makeCountingTool();
      const gated = governTool(tool, {
        scope: { network: false, filesystem: [], credentials: [] },
      });

      const first = await gated.execute({ amount: 100, to: 'acct-1' });
      const second = await gated.execute({ amount: 100, to: 'acct-1' });

      expect(first).toEqual({ chargeId: 1 });
      expect(second).toEqual({ chargeId: 2 });
      expect(calls()).toBe(2);
    });
  });

  describe("TG03 DNS-resolution check runs through governTool()'s real call chain", () => {
    // `execute()` already awaits the classifier, so wiring classifyAsync() through it is what
    // makes this end-to-end test possible in the first place -- these prove that wiring is
    // actually in place, against the real OS resolver (node:dns is not mocked anywhere in this
    // file), not just that the standalone rule works in isolation.
    it('denies a call whose hostname argument resolves (via real DNS/hosts lookup) to loopback', async () => {
      let executed = false;
      const tool: ToolDefinition<{ host: string }, unknown> = {
        name: 'http.get',
        execute: (args) => {
          executed = true;
          return { host: args.host };
        },
      };
      const gated = governTool(tool, {
        scope: { network: ['other.example'], filesystem: [], credentials: [] },
      });

      await expect(gated.execute({ host: 'localhost' })).rejects.toThrow(ToolGovernDenialError);
      expect(executed).toBe(false);
    });

    it('the denial carries the TG03-dns-resolves-private rule ID', async () => {
      const tool: ToolDefinition<{ host: string }, unknown> = {
        name: 'http.get',
        execute: (args) => ({ host: args.host }),
      };
      const gated = governTool(tool, {
        scope: { network: ['other.example'], filesystem: [], credentials: [] },
      });

      try {
        await gated.execute({ host: 'localhost' });
        expect.unreachable('expected governTool to throw for a hostname resolving to loopback');
      } catch (error) {
        expect(error).toBeInstanceOf(ToolGovernDenialError);
        const denial = error as ToolGovernDenialError;
        expect(denial.decisionInfo.firedRules.map((r) => r.ruleId)).toContain(
          'TG03-dns-resolves-private',
        );
      }
    });

    it(
      'a clean call with no host argument at all is unaffected -- classifyAsync does not ' +
        'change ordinary allow behavior for calls the DNS check has nothing to evaluate',
      async () => {
        // Deliberately not asserting an "allow" outcome for any *hostname* argument here: doing so
        // would require the real hostname to actually resolve in whatever sandbox/CI network this
        // suite runs in, which this project has no control over. The no-host case above is the
        // honest way to prove classifyAsync's wiring doesn't regress the plain allow path.
        const result = await governTool(makeShellTool(), {
          scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        }).execute({ command: 'ls ./workspace' });
        expect(result).toEqual({ ran: 'ls ./workspace' });
      },
    );
  });

  describe('pendingApprovals (durable, resumable approval registry)', () => {
    it('registers a durable pending approval BEFORE the synchronous onApprovalRequired callback runs', async () => {
      const registry = new PendingApprovalRegistry();
      let pendingIdWhenHandlerRan: string | undefined;
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        pendingApprovals: registry,
        onApprovalRequired: (info) => {
          // The registry entry must already exist by the time the handler is invoked -- this is
          // the "persist BEFORE invoking the callback" ordering the async-resume path depends on.
          pendingIdWhenHandlerRan = info.pendingId;
          expect(info.pendingId).toBeDefined();
          expect(registry.get(info.pendingId!)?.status).toBe('pending');
          return true;
        },
      });

      await gated.execute({ command: 'sudo apt-get update' });
      expect(pendingIdWhenHandlerRan).toBeDefined();
    });

    it("reflects the synchronous path's outcome back into the registry so it reads 'resolved'", async () => {
      const registry = new PendingApprovalRegistry();
      let seenPendingId: string | undefined;
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        pendingApprovals: registry,
        onDecision: (info) => {
          seenPendingId = info.pendingId;
        },
        onApprovalRequired: () => ({ approved: true, approvedBy: 'alice@example.com' }),
      });

      await gated.execute({ command: 'sudo apt-get update' });

      expect(seenPendingId).toBeDefined();
      const entry = registry.get(seenPendingId!);
      expect(entry?.status).toBe('resolved');
      expect(entry?.resolution).toMatchObject({
        decision: 'allow',
        approvedBy: 'alice@example.com',
      });
    });

    it('a genuine sync-handler decision is terminal: a later out-of-band resolvePending() gets already-resolved', async () => {
      const registry = new PendingApprovalRegistry();
      let seenPendingId: string | undefined;
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        pendingApprovals: registry,
        onDecision: (info) => {
          seenPendingId = info.pendingId;
        },
        // A real, answering handler -- explicitly denies. This is a genuine decision, not a
        // fail-closed default, so it must close out the registry entry.
        onApprovalRequired: () => false,
      });

      await expect(gated.execute({ command: 'sudo apt-get update' })).rejects.toThrow(
        ToolGovernDenialError,
      );

      const outcome = await registry.resolvePending(seenPendingId!, {
        decision: 'allow',
        approvedBy: 'late-approver@example.com',
      });
      expect(outcome.status).toBe('already-resolved');
      // The synchronous handler's genuine deny is what actually happened -- a later resolve
      // cannot retroactively turn that into an allow.
      expect(outcome.finalDecision).toBe('deny');
    });

    it(
      'a fail-closed default (no handler, a timeout, or a throwing handler) is NOT a genuine ' +
        'decision -- the registry entry is left pending so a later async resolution remains possible',
      async () => {
        const registry = new PendingApprovalRegistry();
        let seenPendingId: string | undefined;

        // Case 1: no onApprovalRequired at all.
        const gatedNoHandler = governTool(makeShellTool(), {
          scope: { network: false, filesystem: ['./workspace'], credentials: [] },
          pendingApprovals: registry,
          onDecision: (info) => {
            seenPendingId = info.pendingId;
          },
        });
        await expect(gatedNoHandler.execute({ command: 'sudo apt-get update' })).rejects.toThrow(
          ToolGovernDenialError,
        );
        expect(registry.get(seenPendingId!)?.status).toBe('pending');

        // Case 2: a handler that times out.
        const registry2 = new PendingApprovalRegistry();
        let seenPendingId2: string | undefined;
        const gatedTimeout = governTool(makeShellTool(), {
          scope: { network: false, filesystem: ['./workspace'], credentials: [] },
          pendingApprovals: registry2,
          approvalTimeoutMs: 20,
          onApprovalRequired: () => new Promise(() => {}),
          onDecision: (info) => {
            seenPendingId2 = info.pendingId;
          },
        });
        await expect(gatedTimeout.execute({ command: 'sudo apt-get update' })).rejects.toThrow(
          ToolGovernDenialError,
        );
        expect(registry2.get(seenPendingId2!)?.status).toBe('pending');

        // Case 3: a handler that throws synchronously.
        const registry3 = new PendingApprovalRegistry();
        let seenPendingId3: string | undefined;
        const gatedThrows = governTool(makeShellTool(), {
          scope: { network: false, filesystem: ['./workspace'], credentials: [] },
          pendingApprovals: registry3,
          onApprovalRequired: () => {
            throw new Error('handler blew up');
          },
          onDecision: (info) => {
            seenPendingId3 = info.pendingId;
          },
        });
        await expect(gatedThrows.execute({ command: 'sudo apt-get update' })).rejects.toThrow(
          ToolGovernDenialError,
        );
        expect(registry3.get(seenPendingId3!)?.status).toBe('pending');
      },
    );

    it('with no pendingApprovals registry configured, behavior is unchanged (no regression)', async () => {
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        onApprovalRequired: () => true,
      });
      const result = await gated.execute({ command: 'sudo apt-get update' });
      expect(result).toEqual({ ran: 'sudo apt-get update' });
    });

    it('an allow decision does not register a pending approval at all', async () => {
      const registry = new PendingApprovalRegistry();
      const gated = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        pendingApprovals: registry,
      });
      await gated.execute({ command: 'ls ./workspace' });
      // No way to directly enumerate the registry, but a clean call producing no GateDecisionInfo
      // with a pendingId is itself the proof -- covered by onDecision below.
      let sawPendingId = false;
      const gated2 = governTool(makeShellTool(), {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        pendingApprovals: registry,
        onDecision: (info) => {
          sawPendingId = info.pendingId !== undefined;
        },
      });
      await gated2.execute({ command: 'ls ./workspace' });
      expect(sawPendingId).toBe(false);
    });
  });

  describe('resumePendingApproval() (closing the loop for the async-resume path)', () => {
    it('executes the tool once resolved to allow, and returns its result', async () => {
      const registry = new PendingApprovalRegistry();
      let seenPendingId: string | undefined;
      const tool = makeShellTool();
      const gated = governTool(tool, {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        pendingApprovals: registry,
        onDecision: (info) => {
          seenPendingId = info.pendingId;
        },
      });

      await expect(gated.execute({ command: 'sudo apt-get update' })).rejects.toThrow(
        ToolGovernDenialError,
      );

      const result = await resumePendingApproval(tool, registry, seenPendingId!, {
        decision: 'allow',
        approvedBy: 'alice@example.com',
      });
      expect(result).toEqual({ ran: 'sudo apt-get update' });
    });

    it('populates approvedBy end-to-end on the async-resume trace entry, not only on the sync path', async () => {
      const filePath = await makeTempTraceFile();
      const trace = new TraceWriter(filePath);
      const registry = new PendingApprovalRegistry();
      let seenPendingId: string | undefined;
      const tool = makeShellTool();
      const gated = governTool(tool, {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        pendingApprovals: registry,
        trace,
        agentId: 'coordinator',
        sessionId: 's1',
        onDecision: (info) => {
          seenPendingId = info.pendingId;
        },
      });

      await expect(gated.execute({ command: 'sudo apt-get update' })).rejects.toThrow(
        ToolGovernDenialError,
      );

      await resumePendingApproval(
        tool,
        registry,
        seenPendingId!,
        { decision: 'allow', approvedBy: 'alice@example.com' },
        { trace },
      );

      const raw = await readFile(filePath, 'utf8');
      const lines = raw
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line));
      // Two real trace entries: the synchronous path's fail-closed deny (at the original call),
      // and the async-resume path's allow (once a human actually approved it later) -- each an
      // honest record of what happened at that point in time, chained via prior_trace_id.
      expect(lines).toHaveLength(2);
      expect(lines[0].decision).toBe('deny');
      expect(lines[1].decision).toBe('allow');
      expect(lines[1].approved_by).toBe('alice@example.com');
      expect(lines[1].prior_trace_id).toBe(lines[0].trace_id);
    });

    it('denies (never executes the tool) when the resolution re-classifies edited args to a still-risky call', async () => {
      const registry = new PendingApprovalRegistry();
      let seenPendingId: string | undefined;
      let executed = false;
      const tool: ToolDefinition<{ command: string }, unknown> = {
        name: 'bash',
        execute: (args) => {
          executed = true;
          return { ran: args.command };
        },
      };
      const gated = governTool(tool, {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        pendingApprovals: registry,
        onDecision: (info) => {
          seenPendingId = info.pendingId;
        },
      });

      await expect(gated.execute({ command: 'sudo apt-get update' })).rejects.toThrow(
        ToolGovernDenialError,
      );

      await expect(
        resumePendingApproval(tool, registry, seenPendingId!, {
          decision: 'allow',
          approvedBy: 'alice@example.com',
          editedArgs: { command: 'rm -rf /' },
        }),
      ).rejects.toThrow(ToolGovernDenialError);
      expect(executed).toBe(false);
    });

    it('actually executes the tool with the edited arguments when the edit remains clean', async () => {
      const registry = new PendingApprovalRegistry();
      let seenPendingId: string | undefined;
      const tool = makeShellTool();
      const gated = governTool(tool, {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        pendingApprovals: registry,
        onDecision: (info) => {
          seenPendingId = info.pendingId;
        },
      });

      await expect(gated.execute({ command: 'sudo apt-get update' })).rejects.toThrow(
        ToolGovernDenialError,
      );

      const result = await resumePendingApproval(tool, registry, seenPendingId!, {
        decision: 'allow',
        editedArgs: { command: 'ls ./workspace' },
      });
      expect(result).toEqual({ ran: 'ls ./workspace' });
    });

    it('throws PendingApprovalNotResolvableError for an unrecognized pendingId, never executing the tool', async () => {
      const registry = new PendingApprovalRegistry();
      let executed = false;
      const tool: ToolDefinition<{ command: string }, unknown> = {
        name: 'bash',
        execute: (args) => {
          executed = true;
          return { ran: args.command };
        },
      };

      await expect(
        resumePendingApproval(tool, registry, 'never-registered', { decision: 'allow' }),
      ).rejects.toThrow(PendingApprovalNotResolvableError);
      expect(executed).toBe(false);
    });

    it('resolving by an alias registered after the original call still resumes correctly', async () => {
      const registry = new PendingApprovalRegistry();
      let seenPendingId: string | undefined;
      const tool = makeShellTool();
      const gated = governTool(tool, {
        scope: { network: false, filesystem: ['./workspace'], credentials: [] },
        pendingApprovals: registry,
        onDecision: (info) => {
          seenPendingId = info.pendingId;
        },
      });

      await expect(gated.execute({ command: 'sudo apt-get update' })).rejects.toThrow(
        ToolGovernDenialError,
      );

      registry.registerAlias(seenPendingId!, 'webhook-thread-id-v2');
      const result = await resumePendingApproval(tool, registry, 'webhook-thread-id-v2', {
        decision: 'allow',
      });
      expect(result).toEqual({ ran: 'sudo apt-get update' });
    });
  });
});
