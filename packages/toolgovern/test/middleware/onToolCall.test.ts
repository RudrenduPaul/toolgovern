import { describe, expect, it, afterEach } from 'vitest';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { governTool, ToolGovernDenialError } from '../../src/middleware/onToolCall.js';
import type { ToolDefinition } from '../../src/middleware/onToolCall.js';
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

    it('records the final decision (allow) in the trace after a human approves, not the classifier\'s original require-approval decision', async () => {
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

    it('records the final decision (deny) in the trace after a human denies, not the classifier\'s original require-approval decision', async () => {
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
});
