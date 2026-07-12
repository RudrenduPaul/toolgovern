import { describe, expect, it } from 'vitest';
import { crossAgentInheritanceRules } from '../../src/classifier/cross-agent-inheritance.js';
import { ScopeRegistry } from '../../src/scoping/inheritance-enforcer.js';
import type { RuleContext } from '../../src/types.js';

function rule(id: string) {
  const found = crossAgentInheritanceRules.find((r) => r.id === id);
  if (!found) throw new Error(`No such rule: ${id}`);
  return found;
}

describe('TG05 cross-agent privilege inheritance', () => {
  describe('TG05-unregistered-sub-agent', () => {
    it('flags a call from a declared sub-agent with no registry record', () => {
      const registry = new ScopeRegistry();
      const ctx: RuleContext = {
        agentId: 'ghost-sub',
        sessionId: 's1',
        coordinatorId: 'coordinator',
        tool: 'bash',
        args: { command: 'ls' },
        scope: { network: false, filesystem: [], credentials: [] },
        scopeRegistry: registry,
      };
      expect(rule('TG05-unregistered-sub-agent').evaluate(ctx)).not.toBeNull();
    });

    it('does not flag a registered sub-agent', () => {
      const registry = new ScopeRegistry();
      registry.registerRootAgent('coordinator', 's1', {
        network: ['example.com'],
        filesystem: ['./workspace'],
        credentials: [],
      });
      registry.spawnSubAgent({
        coordinatorId: 'coordinator',
        subAgentId: 'research-sub',
        sessionId: 's1',
        requestedScope: { network: ['example.com'], filesystem: ['./workspace'], credentials: [] },
      });
      const ctx: RuleContext = {
        agentId: 'research-sub',
        sessionId: 's1',
        coordinatorId: 'coordinator',
        tool: 'bash',
        args: { command: 'ls' },
        scope: { network: ['example.com'], filesystem: ['./workspace'], credentials: [] },
        scopeRegistry: registry,
      };
      expect(rule('TG05-unregistered-sub-agent').evaluate(ctx)).toBeNull();
    });

    it('does not flag a root agent with no coordinator', () => {
      const registry = new ScopeRegistry();
      const ctx: RuleContext = {
        agentId: 'coordinator',
        sessionId: 's1',
        tool: 'bash',
        args: { command: 'ls' },
        scope: { network: false, filesystem: [], credentials: [] },
        scopeRegistry: registry,
      };
      expect(rule('TG05-unregistered-sub-agent').evaluate(ctx)).toBeNull();
    });
  });

  describe('TG05-zero-capability-sub-agent', () => {
    it('denies any tool call from a sub-agent granted zero capability at all', () => {
      const registry = new ScopeRegistry();
      registry.registerRootAgent('coordinator', 's1', {
        network: false,
        filesystem: [],
        credentials: [],
      });
      // Coordinator itself has nothing to grant, so this sub-agent's request is intersected
      // down to the empty scope no matter what it asked for.
      registry.spawnSubAgent({
        coordinatorId: 'coordinator',
        subAgentId: 'no-tools-sub',
        sessionId: 's1',
        requestedScope: {
          network: true,
          filesystem: ['/'],
          credentials: ['anything'],
        },
      });
      const grantedScope = registry.getEffectiveScope('no-tools-sub')!;
      expect(grantedScope).toEqual({ network: false, filesystem: [], credentials: [] });

      // A tool call whose arguments contain nothing any other rule's extraction recognizes --
      // no path, host, or credential key -- so without this rule it would fall through
      // unclassified and be allowed by default.
      const ctx: RuleContext = {
        agentId: 'no-tools-sub',
        sessionId: 's1',
        coordinatorId: 'coordinator',
        tool: 'run_query',
        args: { query: 'SELECT 1' },
        scope: grantedScope,
        scopeRegistry: registry,
      };
      expect(rule('TG05-zero-capability-sub-agent').evaluate(ctx)).not.toBeNull();
      expect(rule('TG05-zero-capability-sub-agent').evaluate(ctx)?.decision).toBe('deny');
    });

    it('also denies a recognizable tool call (e.g. a filesystem path) from a zero-capability sub-agent', () => {
      const registry = new ScopeRegistry();
      registry.registerRootAgent('coordinator', 's1', {
        network: false,
        filesystem: [],
        credentials: [],
      });
      registry.spawnSubAgent({
        coordinatorId: 'coordinator',
        subAgentId: 'no-tools-sub',
        sessionId: 's1',
        requestedScope: { network: false, filesystem: ['/tmp'], credentials: [] },
      });
      const grantedScope = registry.getEffectiveScope('no-tools-sub')!;
      const ctx: RuleContext = {
        agentId: 'no-tools-sub',
        sessionId: 's1',
        coordinatorId: 'coordinator',
        tool: 'fs.read',
        args: { path: '/tmp/anything.txt', operation: 'read' },
        scope: grantedScope,
        scopeRegistry: registry,
      };
      expect(rule('TG05-zero-capability-sub-agent').evaluate(ctx)).not.toBeNull();
    });

    it('does not flag a sub-agent that was granted at least one capability', () => {
      const registry = new ScopeRegistry();
      registry.registerRootAgent('coordinator', 's1', {
        network: false,
        filesystem: ['./workspace'],
        credentials: [],
      });
      registry.spawnSubAgent({
        coordinatorId: 'coordinator',
        subAgentId: 'scoped-sub',
        sessionId: 's1',
        requestedScope: { network: false, filesystem: ['./workspace'], credentials: [] },
      });
      const grantedScope = registry.getEffectiveScope('scoped-sub')!;
      const ctx: RuleContext = {
        agentId: 'scoped-sub',
        sessionId: 's1',
        coordinatorId: 'coordinator',
        tool: 'run_query',
        args: { query: 'SELECT 1' },
        scope: grantedScope,
        scopeRegistry: registry,
      };
      expect(rule('TG05-zero-capability-sub-agent').evaluate(ctx)).toBeNull();
    });

    it('does not flag a root agent (no coordinator) even with an empty declared scope', () => {
      const registry = new ScopeRegistry();
      registry.registerRootAgent('lone-root', 's1', {
        network: false,
        filesystem: [],
        credentials: [],
      });
      const ctx: RuleContext = {
        agentId: 'lone-root',
        sessionId: 's1',
        tool: 'run_query',
        args: { query: 'SELECT 1' },
        scope: { network: false, filesystem: [], credentials: [] },
        scopeRegistry: registry,
      };
      expect(rule('TG05-zero-capability-sub-agent').evaluate(ctx)).toBeNull();
    });

    it('does not flag when there is no registry record at all', () => {
      const ctx: RuleContext = {
        agentId: 'ghost-sub',
        sessionId: 's1',
        coordinatorId: 'coordinator',
        tool: 'run_query',
        args: { query: 'SELECT 1' },
        scope: { network: false, filesystem: [], credentials: [] },
        scopeRegistry: new ScopeRegistry(),
      };
      // Left to TG05-unregistered-sub-agent to flag instead.
      expect(rule('TG05-zero-capability-sub-agent').evaluate(ctx)).toBeNull();
    });
  });

  function buildEscalationRegistry(): ScopeRegistry {
    const registry = new ScopeRegistry();
    // Coordinator only has ./workspace and no credentials -- narrower than what the sub-agent
    // will *request*, so requests beyond it get silently dropped during spawn (default-deny).
    registry.registerRootAgent('coordinator', 's1', {
      network: false,
      filesystem: ['./workspace'],
      credentials: [],
    });
    registry.spawnSubAgent({
      coordinatorId: 'coordinator',
      subAgentId: 'research-sub',
      sessionId: 's1',
      // Sub-agent asks for more than the coordinator has -- credentials it was never granted.
      requestedScope: {
        network: false,
        filesystem: ['./workspace'],
        credentials: ['.aws/credentials'],
      },
    });
    return registry;
  }

  describe('TG05-credential-exceeds-grant', () => {
    it('flags a call for a credential the agent requested but was never granted', () => {
      const registry = buildEscalationRegistry();
      const grantedScope = registry.getEffectiveScope('research-sub')!;
      const ctx: RuleContext = {
        agentId: 'research-sub',
        sessionId: 's1',
        coordinatorId: 'coordinator',
        tool: 'fs.read',
        args: { path: '.aws/credentials' },
        scope: grantedScope,
        scopeRegistry: registry,
      };
      expect(rule('TG05-credential-exceeds-grant').evaluate(ctx)).not.toBeNull();
    });

    it('does not flag a credential that was both requested and granted', () => {
      const registry = new ScopeRegistry();
      registry.registerRootAgent('coordinator', 's1', {
        network: false,
        filesystem: [],
        credentials: ['.aws/credentials'],
      });
      registry.spawnSubAgent({
        coordinatorId: 'coordinator',
        subAgentId: 'export-sub',
        sessionId: 's1',
        requestedScope: { network: false, filesystem: [], credentials: ['.aws/credentials'] },
      });
      const grantedScope = registry.getEffectiveScope('export-sub')!;
      const ctx: RuleContext = {
        agentId: 'export-sub',
        sessionId: 's1',
        coordinatorId: 'coordinator',
        tool: 'fs.read',
        args: { path: '.aws/credentials' },
        scope: grantedScope,
        scopeRegistry: registry,
      };
      expect(rule('TG05-credential-exceeds-grant').evaluate(ctx)).toBeNull();
    });

    it('does not flag when there is no registry record at all', () => {
      const ctx: RuleContext = {
        agentId: 'lone-agent',
        sessionId: 's1',
        tool: 'fs.read',
        args: { path: '.aws/credentials' },
        scope: { network: false, filesystem: [], credentials: [] },
      };
      expect(rule('TG05-credential-exceeds-grant').evaluate(ctx)).toBeNull();
    });
  });

  describe('TG05-network-exceeds-grant', () => {
    it('flags a host requested but never granted by the coordinator', () => {
      const registry = new ScopeRegistry();
      registry.registerRootAgent('coordinator', 's1', {
        network: false,
        filesystem: [],
        credentials: [],
      });
      registry.spawnSubAgent({
        coordinatorId: 'coordinator',
        subAgentId: 'research-sub',
        sessionId: 's1',
        requestedScope: { network: ['attacker.io'], filesystem: [], credentials: [] },
      });
      const grantedScope = registry.getEffectiveScope('research-sub')!;
      const ctx: RuleContext = {
        agentId: 'research-sub',
        sessionId: 's1',
        coordinatorId: 'coordinator',
        tool: 'http.get',
        args: { host: 'attacker.io' },
        scope: grantedScope,
        scopeRegistry: registry,
      };
      expect(rule('TG05-network-exceeds-grant').evaluate(ctx)).not.toBeNull();
    });

    it('does not flag a host that is both requested and granted', () => {
      const registry = new ScopeRegistry();
      registry.registerRootAgent('coordinator', 's1', {
        network: ['example.com'],
        filesystem: [],
        credentials: [],
      });
      registry.spawnSubAgent({
        coordinatorId: 'coordinator',
        subAgentId: 'research-sub',
        sessionId: 's1',
        requestedScope: { network: ['example.com'], filesystem: [], credentials: [] },
      });
      const grantedScope = registry.getEffectiveScope('research-sub')!;
      const ctx: RuleContext = {
        agentId: 'research-sub',
        sessionId: 's1',
        coordinatorId: 'coordinator',
        tool: 'http.get',
        args: { host: 'example.com' },
        scope: grantedScope,
        scopeRegistry: registry,
      };
      expect(rule('TG05-network-exceeds-grant').evaluate(ctx)).toBeNull();
    });
  });

  describe('TG05-filesystem-exceeds-grant', () => {
    it('flags a path requested but never granted by the coordinator', () => {
      const registry = new ScopeRegistry();
      registry.registerRootAgent('coordinator', 's1', {
        network: false,
        filesystem: ['./workspace'],
        credentials: [],
      });
      registry.spawnSubAgent({
        coordinatorId: 'coordinator',
        subAgentId: 'export-sub',
        sessionId: 's1',
        requestedScope: { network: false, filesystem: ['./workspace', '/tmp'], credentials: [] },
      });
      const grantedScope = registry.getEffectiveScope('export-sub')!;
      const ctx: RuleContext = {
        agentId: 'export-sub',
        sessionId: 's1',
        coordinatorId: 'coordinator',
        tool: 'fs.write',
        args: { path: '/tmp/export.csv', operation: 'write' },
        scope: grantedScope,
        scopeRegistry: registry,
      };
      expect(rule('TG05-filesystem-exceeds-grant').evaluate(ctx)).not.toBeNull();
    });

    it('does not flag a path within what was granted', () => {
      const registry = new ScopeRegistry();
      registry.registerRootAgent('coordinator', 's1', {
        network: false,
        filesystem: ['./workspace'],
        credentials: [],
      });
      registry.spawnSubAgent({
        coordinatorId: 'coordinator',
        subAgentId: 'export-sub',
        sessionId: 's1',
        requestedScope: { network: false, filesystem: ['./workspace'], credentials: [] },
      });
      const grantedScope = registry.getEffectiveScope('export-sub')!;
      const ctx: RuleContext = {
        agentId: 'export-sub',
        sessionId: 's1',
        coordinatorId: 'coordinator',
        tool: 'fs.write',
        args: { path: './workspace/out.csv', operation: 'write' },
        scope: grantedScope,
        scopeRegistry: registry,
      };
      expect(rule('TG05-filesystem-exceeds-grant').evaluate(ctx)).toBeNull();
    });
  });

  describe('TG05-coordinator-scope-shrunk', () => {
    it('flags a call once the coordinator no longer covers a previously granted credential', () => {
      const registry = new ScopeRegistry();
      registry.registerRootAgent('coordinator', 's1', {
        network: false,
        filesystem: [],
        credentials: ['.aws/credentials'],
      });
      registry.spawnSubAgent({
        coordinatorId: 'coordinator',
        subAgentId: 'export-sub',
        sessionId: 's1',
        requestedScope: { network: false, filesystem: [], credentials: ['.aws/credentials'] },
      });
      // Coordinator's own scope is later reduced (e.g. re-registered with a narrower policy).
      registry.registerRootAgent('coordinator', 's1', {
        network: false,
        filesystem: [],
        credentials: [],
      });

      const grantedScope = registry.getEffectiveScope('export-sub')!;
      const ctx: RuleContext = {
        agentId: 'export-sub',
        sessionId: 's1',
        coordinatorId: 'coordinator',
        tool: 'fs.read',
        args: { path: '.aws/credentials' },
        scope: grantedScope,
        scopeRegistry: registry,
      };
      expect(rule('TG05-coordinator-scope-shrunk').evaluate(ctx)).not.toBeNull();
    });

    it('does not flag when the coordinator scope is unchanged', () => {
      const registry = new ScopeRegistry();
      registry.registerRootAgent('coordinator', 's1', {
        network: false,
        filesystem: [],
        credentials: ['.aws/credentials'],
      });
      registry.spawnSubAgent({
        coordinatorId: 'coordinator',
        subAgentId: 'export-sub',
        sessionId: 's1',
        requestedScope: { network: false, filesystem: [], credentials: ['.aws/credentials'] },
      });
      const grantedScope = registry.getEffectiveScope('export-sub')!;
      const ctx: RuleContext = {
        agentId: 'export-sub',
        sessionId: 's1',
        coordinatorId: 'coordinator',
        tool: 'fs.read',
        args: { path: '.aws/credentials' },
        scope: grantedScope,
        scopeRegistry: registry,
      };
      expect(rule('TG05-coordinator-scope-shrunk').evaluate(ctx)).toBeNull();
    });
  });

  it('every rule has a unique id and belongs to TG05', () => {
    const ids = new Set(crossAgentInheritanceRules.map((r) => r.id));
    expect(ids.size).toBe(crossAgentInheritanceRules.length);
    for (const r of crossAgentInheritanceRules) {
      expect(r.category).toBe('TG05');
    }
  });
});
