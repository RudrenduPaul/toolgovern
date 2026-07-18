import { describe, expect, it } from 'vitest';
import {
  PendingApprovalAliasConflictError,
  PendingApprovalRegistry,
  UnknownPendingApprovalError,
} from '../../src/approval/pending-registry.js';
import type { RuleMatch, ScopeDeclaration } from '../../src/types.js';

const scope: ScopeDeclaration = { network: false, filesystem: ['./workspace'], credentials: [] };

function makeRegistry(overrides: ConstructorParameters<typeof PendingApprovalRegistry>[0] = {}) {
  let counter = 0;
  return new PendingApprovalRegistry({
    idFactory: () => `pending-${++counter}`,
    ...overrides,
  });
}

function sudoFiredRules(): RuleMatch[] {
  return [
    {
      ruleId: 'TG01-sudo',
      category: 'TG01',
      decision: 'require-approval',
      reason: 'sudo invocation',
      matchedArgument: 'command',
    },
  ];
}

describe('PendingApprovalRegistry', () => {
  describe('register -> resolve happy path', () => {
    it('registers a pending approval and resolves it to allow', async () => {
      const registry = makeRegistry();
      const pendingId = registry.registerPending({
        agentId: 'agent-1',
        sessionId: 'session-1',
        tool: 'bash',
        args: { command: 'sudo apt-get update' },
        scope,
        firedRules: sudoFiredRules(),
      });

      expect(pendingId).toBe('pending-1');
      expect(registry.get(pendingId)?.status).toBe('pending');

      const outcome = await registry.resolvePending(pendingId, {
        decision: 'allow',
        approvedBy: 'alice@example.com',
      });

      expect(outcome).toMatchObject({
        status: 'resolved',
        pendingId,
        finalDecision: 'allow',
        approvedBy: 'alice@example.com',
        args: { command: 'sudo apt-get update' },
      });
      expect(registry.get(pendingId)?.status).toBe('resolved');
      expect(registry.get(pendingId)?.resolution?.approvedBy).toBe('alice@example.com');
    });

    it('resolves a pending approval to deny', async () => {
      const registry = makeRegistry();
      const pendingId = registry.registerPending({
        agentId: 'agent-1',
        sessionId: 'session-1',
        tool: 'bash',
        args: { command: 'sudo apt-get update' },
        scope,
        firedRules: sudoFiredRules(),
      });

      const outcome = await registry.resolvePending(pendingId, {
        decision: 'deny',
        approvedBy: 'bob@example.com',
      });

      expect(outcome.status).toBe('resolved');
      expect(outcome.finalDecision).toBe('deny');
    });

    it('a second resolve of the same id returns already-resolved, not a fresh decision', async () => {
      const registry = makeRegistry();
      const pendingId = registry.registerPending({
        agentId: 'agent-1',
        sessionId: 'session-1',
        tool: 'bash',
        args: { command: 'sudo apt-get update' },
        scope,
        firedRules: sudoFiredRules(),
      });

      await registry.resolvePending(pendingId, {
        decision: 'allow',
        approvedBy: 'alice@example.com',
      });
      const second = await registry.resolvePending(pendingId, {
        decision: 'deny',
        approvedBy: 'mallory@example.com',
      });

      expect(second.status).toBe('already-resolved');
      // The FIRST resolution's outcome wins -- a later call can never flip it.
      expect(second.finalDecision).toBe('allow');
      expect(second.approvedBy).toBe('alice@example.com');
    });
  });

  describe('resolve-by-alias after alias rewrite (microsoft/agent-framework#6908)', () => {
    it('resolves a pending approval by an alias registered after the original id', async () => {
      const registry = makeRegistry();
      const pendingId = registry.registerPending({
        agentId: 'agent-1',
        sessionId: 'thread-original',
        tool: 'bash',
        args: { command: 'sudo apt-get update' },
        scope,
        firedRules: sudoFiredRules(),
      });

      // A stateful provider rewrites the thread id mid-stream; the caller learns the new id and
      // records it as an alias for the same pending approval, exactly as MAF PR #6908 does for
      // AG-UI's client-thread-id vs. provider-conversation-id mismatch.
      registry.registerAlias(pendingId, 'thread-rewritten-by-provider');

      const byOriginal = registry.get(pendingId);
      const byAlias = registry.get('thread-rewritten-by-provider');
      expect(byOriginal?.pendingId).toBe(pendingId);
      expect(byAlias?.pendingId).toBe(pendingId);
      expect(byAlias?.aliases).toContain('thread-rewritten-by-provider');

      // Resolving with the client's ORIGINAL thread id must still work even though the provider
      // has since rewritten it -- this is the exact failure mode #6908 fixed: before that fix, a
      // client resuming with its own original id could not find its own pending approval because
      // it had been registered only under the post-rewrite id.
      const outcome = await registry.resolvePending(pendingId, {
        decision: 'allow',
        approvedBy: 'alice@example.com',
      });
      expect(outcome.status).toBe('resolved');
    });

    it('resolving by the alias also works, and consumes the same shared entry (no double-resolution)', async () => {
      const registry = makeRegistry();
      const pendingId = registry.registerPending({
        agentId: 'agent-1',
        sessionId: 'thread-original',
        tool: 'bash',
        args: { command: 'sudo apt-get update' },
        scope,
        firedRules: sudoFiredRules(),
      });
      registry.registerAlias(pendingId, 'thread-rewritten-by-provider');

      const resolvedByAlias = await registry.resolvePending('thread-rewritten-by-provider', {
        decision: 'allow',
        approvedBy: 'alice@example.com',
      });
      expect(resolvedByAlias.status).toBe('resolved');

      // Now resolving by the ORIGINAL id (the shared entry was already consumed via the alias)
      // must report already-resolved, not silently re-decide or re-execute.
      const resolvedAgainByOriginal = await registry.resolvePending(pendingId, {
        decision: 'deny',
      });
      expect(resolvedAgainByOriginal.status).toBe('already-resolved');
      expect(resolvedAgainByOriginal.finalDecision).toBe('allow');
    });

    it('registerAlias throws for an unrecognized pendingId (never plants a phantom entry)', () => {
      const registry = makeRegistry();
      expect(() => registry.registerAlias('does-not-exist', 'some-alias')).toThrow(
        UnknownPendingApprovalError,
      );
    });

    it('registerAlias throws when the alias already refers to a different pending approval', () => {
      const registry = makeRegistry();
      const first = registry.registerPending({
        agentId: 'agent-1',
        sessionId: 's1',
        tool: 'bash',
        args: { command: 'a' },
        scope,
        firedRules: sudoFiredRules(),
      });
      const second = registry.registerPending({
        agentId: 'agent-1',
        sessionId: 's2',
        tool: 'bash',
        args: { command: 'b' },
        scope,
        firedRules: sudoFiredRules(),
      });
      registry.registerAlias(first, 'shared-alias');
      expect(() => registry.registerAlias(second, 'shared-alias')).toThrow(
        PendingApprovalAliasConflictError,
      );
    });
  });

  describe('edited-args re-classification (must never bypass the classifier)', () => {
    it('denies edited args that would themselves trigger a deny, even after approval', async () => {
      const registry = makeRegistry();
      const pendingId = registry.registerPending({
        agentId: 'agent-1',
        sessionId: 's1',
        tool: 'bash',
        args: { command: 'sudo apt-get update' },
        scope,
        firedRules: sudoFiredRules(),
      });

      // The human clicks "approve", but edits the arguments to something the classifier itself
      // would deny outright (TG01-rm-rf) -- approving must not smuggle this through.
      const outcome = await registry.resolvePending(pendingId, {
        decision: 'allow',
        approvedBy: 'alice@example.com',
        editedArgs: { command: 'rm -rf /' },
      });

      expect(outcome.status).toBe('resolved');
      expect(outcome.finalDecision).toBe('deny');
      expect(outcome.args).toEqual({ command: 'rm -rf /' });
      expect(outcome.firedRules?.map((r) => r.ruleId)).toContain('TG01-rm-rf');

      // The registry's own record must reflect the OVERRIDDEN decision, not the human's raw
      // input -- an auditor reading this entry later must see "denied", not "approved".
      expect(registry.get(pendingId)?.resolution?.decision).toBe('deny');
    });

    it('allows edited args that remain clean under the classifier', async () => {
      const registry = makeRegistry();
      const pendingId = registry.registerPending({
        agentId: 'agent-1',
        sessionId: 's1',
        tool: 'bash',
        args: { command: 'sudo apt-get update' },
        scope,
        firedRules: sudoFiredRules(),
      });

      const outcome = await registry.resolvePending(pendingId, {
        decision: 'allow',
        approvedBy: 'alice@example.com',
        editedArgs: { command: 'ls ./workspace' },
      });

      expect(outcome.status).toBe('resolved');
      expect(outcome.finalDecision).toBe('allow');
      expect(outcome.args).toEqual({ command: 'ls ./workspace' });
    });

    it('applies the same rule overrides captured at registration time to the re-classification', async () => {
      const registry = makeRegistry();
      const pendingId = registry.registerPending({
        agentId: 'agent-1',
        sessionId: 's1',
        tool: 'bash',
        args: { command: 'sudo apt-get update' },
        scope,
        firedRules: sudoFiredRules(),
        disabledRules: ['TG01-rm-rf'],
      });

      // TG01-rm-rf was disabled for this call's original classification; the edited-args
      // re-classification must honor the same override, not some different default.
      const outcome = await registry.resolvePending(pendingId, {
        decision: 'allow',
        editedArgs: { command: 'rm -rf /' },
      });

      expect(outcome.finalDecision).toBe('allow');
    });

    it('a deny resolution with editedArgs does not trigger re-classification at all', async () => {
      let reclassifyCalls = 0;
      const registry = makeRegistry({
        reclassify: async (ctx, options) => {
          reclassifyCalls += 1;
          const { classifyAsync } = await import('../../src/classifier/index.js');
          return classifyAsync(ctx, options);
        },
      });
      const pendingId = registry.registerPending({
        agentId: 'agent-1',
        sessionId: 's1',
        tool: 'bash',
        args: { command: 'sudo apt-get update' },
        scope,
        firedRules: sudoFiredRules(),
      });

      const outcome = await registry.resolvePending(pendingId, {
        decision: 'deny',
        editedArgs: { command: 'ls ./workspace' },
      });

      expect(outcome.finalDecision).toBe('deny');
      expect(reclassifyCalls).toBe(0);
    });
  });

  describe('the resume-token bypass this guards against (langchain-ai/langgraph#8169)', () => {
    it('resolvePending never creates a new pending approval for an unrecognized id', async () => {
      const registry = makeRegistry();
      const outcome = await registry.resolvePending('attacker-chosen-id', {
        decision: 'allow',
        approvedBy: 'mallory@example.com',
      });

      expect(outcome.status).toBe('not-found');
      expect(outcome.finalDecision).toBeUndefined();
      // Nothing was created -- a subsequent register still starts fresh at pending-1, and the
      // attacker-chosen id resolves to nothing no matter how many times it's retried.
      expect(registry.get('attacker-chosen-id')).toBeUndefined();

      const secondAttempt = await registry.resolvePending('attacker-chosen-id', {
        decision: 'allow',
      });
      expect(secondAttempt.status).toBe('not-found');
    });

    it('pendingId is always server-generated -- registerPending never accepts a caller-supplied id', () => {
      const registry = makeRegistry();
      const details = {
        agentId: 'agent-1',
        sessionId: 's1',
        tool: 'bash',
        args: { command: 'ls' },
        scope,
        firedRules: [],
      };
      // registerPending's parameter type has no `pendingId` field at all -- there is no way to
      // pass one in, by construction. This test documents that (rather than merely asserting a
      // runtime behavior a future refactor could silently break) by registering twice and
      // checking both ids came from the injected idFactory, never from `details`.
      const first = registry.registerPending(details);
      const second = registry.registerPending(details);
      expect(first).toBe('pending-1');
      expect(second).toBe('pending-2');
      expect(first).not.toBe(second);
    });
  });

  describe('expiry', () => {
    it('an expired pending approval cannot be resolved', async () => {
      let now = 1_000_000;
      const registry = makeRegistry({ now: () => now });
      const pendingId = registry.registerPending({
        agentId: 'agent-1',
        sessionId: 's1',
        tool: 'bash',
        args: { command: 'sudo apt-get update' },
        scope,
        firedRules: sudoFiredRules(),
        ttlMs: 1_000,
      });

      now += 5_000;
      const outcome = await registry.resolvePending(pendingId, { decision: 'allow' });
      expect(outcome.status).toBe('expired');
      expect(registry.get(pendingId)?.status).toBe('expired');
    });

    it('with no ttlMs, a pending approval never expires on its own', async () => {
      let now = 1_000_000;
      const registry = makeRegistry({ now: () => now });
      const pendingId = registry.registerPending({
        agentId: 'agent-1',
        sessionId: 's1',
        tool: 'bash',
        args: { command: 'sudo apt-get update' },
        scope,
        firedRules: sudoFiredRules(),
      });

      now += 1_000_000_000;
      const outcome = await registry.resolvePending(pendingId, { decision: 'allow' });
      expect(outcome.status).toBe('resolved');
    });
  });

  describe('get()', () => {
    it('returns undefined for an unregistered id', () => {
      const registry = makeRegistry();
      expect(registry.get('never-registered')).toBeUndefined();
    });
  });
});
