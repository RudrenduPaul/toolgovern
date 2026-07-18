import { describe, expect, it } from 'vitest';
import {
  ScopeRegistry,
  computeInheritedScope,
  hasZeroCapability,
} from '../../src/scoping/inheritance-enforcer.js';
import { EMPTY_SCOPE } from '../../src/scoping/scope-declaration.js';

describe('computeInheritedScope', () => {
  it('grants the intersection of coordinator and requested filesystem prefixes', () => {
    const granted = computeInheritedScope(
      { network: false, filesystem: ['./workspace'], credentials: [] },
      { network: false, filesystem: ['./workspace', '/etc'], credentials: [] },
    );
    expect(granted.filesystem).toEqual(['./workspace']);
  });

  it('never grants network access the coordinator does not have', () => {
    const granted = computeInheritedScope(
      { network: false, filesystem: [], credentials: [] },
      { network: true, filesystem: [], credentials: [] },
    );
    expect(granted.network).toBe(false);
  });

  it('grants unrestricted network when both coordinator and request are unrestricted', () => {
    const granted = computeInheritedScope(
      { network: true, filesystem: [], credentials: [] },
      { network: true, filesystem: [], credentials: [] },
    );
    expect(granted.network).toBe(true);
  });

  it('caps an unrestricted request to the coordinator allowlist', () => {
    const granted = computeInheritedScope(
      { network: ['example.com'], filesystem: [], credentials: [] },
      { network: true, filesystem: [], credentials: [] },
    );
    expect(granted.network).toEqual(['example.com']);
  });

  it('intersects two explicit host allowlists', () => {
    const granted = computeInheritedScope(
      { network: ['example.com', 'api.example.com'], filesystem: [], credentials: [] },
      { network: ['example.com', 'attacker.io'], filesystem: [], credentials: [] },
    );
    // 'api.example.com' is kept: it is a subdomain of the requested 'example.com', consistent
    // with how an allowlist entry covers subdomains everywhere else (see hostMatchesAllowed).
    // 'attacker.io' is dropped: the coordinator never had it in the first place.
    expect(granted.network).toEqual(['example.com', 'api.example.com']);
  });

  it('drops a coordinator host that has no match anywhere in the request', () => {
    const granted = computeInheritedScope(
      { network: ['example.com', 'internal.corp'], filesystem: [], credentials: [] },
      { network: ['example.com'], filesystem: [], credentials: [] },
    );
    expect(granted.network).toEqual(['example.com']);
  });

  it("grants exactly the narrower requested host, not the coordinator's broader domain grant", () => {
    // A sub-agent that requests a specific host under a domain the coordinator holds broadly
    // must be granted that specific host, not widened out to the coordinator's whole domain
    // -- filtering only the coordinator list (the original bug) returned ['example.com'] here
    // instead of the single host actually requested.
    const granted = computeInheritedScope(
      { network: ['example.com'], filesystem: [], credentials: [] },
      { network: ['api.example.com'], filesystem: [], credentials: [] },
    );
    expect(granted.network).toEqual(['api.example.com']);
  });

  it('never grants a credential the coordinator does not have', () => {
    const granted = computeInheritedScope(
      { network: false, filesystem: [], credentials: [] },
      { network: false, filesystem: [], credentials: ['.aws/credentials'] },
    );
    expect(granted.credentials).toEqual([]);
  });

  it('grants a credential present in both coordinator and request', () => {
    const granted = computeInheritedScope(
      { network: false, filesystem: [], credentials: ['.aws/credentials'] },
      { network: false, filesystem: [], credentials: ['.aws/credentials'] },
    );
    expect(granted.credentials).toEqual(['.aws/credentials']);
  });

  it('requesting nothing grants nothing, even if the coordinator has broad access', () => {
    const granted = computeInheritedScope(
      { network: true, filesystem: ['./workspace', '/data'], credentials: ['api-key'] },
      EMPTY_SCOPE,
    );
    expect(granted).toEqual(EMPTY_SCOPE);
  });
});

describe('ScopeRegistry', () => {
  it('registers a root agent with its own declared scope', () => {
    const registry = new ScopeRegistry();
    const record = registry.registerRootAgent('coordinator', 's1', {
      network: ['example.com'],
      filesystem: ['./workspace'],
      credentials: [],
    });
    expect(record.grantedScope.network).toEqual(['example.com']);
    expect(registry.has('coordinator')).toBe(true);
  });

  it('a sub-agent never exceeds its coordinator granted scope', () => {
    const registry = new ScopeRegistry();
    registry.registerRootAgent('coordinator', 's1', {
      network: false,
      filesystem: ['./workspace'],
      credentials: [],
    });

    const subRecord = registry.spawnSubAgent({
      coordinatorId: 'coordinator',
      subAgentId: 'research-sub',
      sessionId: 's1',
      requestedScope: {
        network: true, // over-asks for unrestricted network
        filesystem: ['./workspace', '/etc'], // over-asks for a system path
        credentials: ['.aws/credentials'], // over-asks for a credential
      },
    });

    expect(subRecord.grantedScope.network).toBe(false);
    expect(subRecord.grantedScope.filesystem).toEqual(['./workspace']);
    expect(subRecord.grantedScope.credentials).toEqual([]);
  });

  it('an unregistered coordinator yields the empty scope for its sub-agent (default-deny)', () => {
    const registry = new ScopeRegistry();
    const subRecord = registry.spawnSubAgent({
      coordinatorId: 'never-registered',
      subAgentId: 'sub',
      sessionId: 's1',
      requestedScope: { network: true, filesystem: ['/'], credentials: ['anything'] },
    });
    expect(subRecord.grantedScope).toEqual(EMPTY_SCOPE);
  });

  it('a grandchild sub-agent cannot exceed its parent, which cannot exceed the root', () => {
    const registry = new ScopeRegistry();
    registry.registerRootAgent('root', 's1', {
      network: ['example.com'],
      filesystem: ['./workspace'],
      credentials: [],
    });
    registry.spawnSubAgent({
      coordinatorId: 'root',
      subAgentId: 'mid',
      sessionId: 's1',
      requestedScope: {
        network: ['example.com'],
        filesystem: ['./workspace/sub'],
        credentials: [],
      },
    });
    const grandchild = registry.spawnSubAgent({
      coordinatorId: 'mid',
      subAgentId: 'leaf',
      sessionId: 's1',
      requestedScope: { network: true, filesystem: ['./workspace', '/'], credentials: [] },
    });
    // leaf asked for the whole workspace and root, but mid only ever had ./workspace/sub
    expect(grandchild.grantedScope.filesystem).toEqual([]);
    expect(grandchild.grantedScope.network).toEqual(['example.com']);
  });

  it('getEffectiveScope returns undefined for an unknown agent', () => {
    const registry = new ScopeRegistry();
    expect(registry.getEffectiveScope('nobody')).toBeUndefined();
    expect(registry.getRecord('nobody')).toBeUndefined();
    expect(registry.has('nobody')).toBe(false);
  });

  describe('isZeroCapability', () => {
    it('is true for a sub-agent whose coordinator had nothing to grant', () => {
      const registry = new ScopeRegistry();
      registry.registerRootAgent('coordinator', 's1', EMPTY_SCOPE);
      registry.spawnSubAgent({
        coordinatorId: 'coordinator',
        subAgentId: 'no-tools-sub',
        sessionId: 's1',
        requestedScope: { network: true, filesystem: ['/'], credentials: ['anything'] },
      });
      expect(registry.isZeroCapability('no-tools-sub')).toBe(true);
    });

    it('is false once the coordinator grants even one capability', () => {
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
      expect(registry.isZeroCapability('scoped-sub')).toBe(false);
    });

    it('is false for an unregistered agent (that case is a different failure mode)', () => {
      const registry = new ScopeRegistry();
      expect(registry.isZeroCapability('nobody')).toBe(false);
    });
  });
});

describe('hasZeroCapability', () => {
  it('is true for the empty scope', () => {
    expect(hasZeroCapability(EMPTY_SCOPE)).toBe(true);
  });

  it('is false when network is unrestricted even with no filesystem/credentials', () => {
    expect(hasZeroCapability({ network: true, filesystem: [], credentials: [] })).toBe(false);
  });

  it('is false when network is a non-empty allowlist', () => {
    expect(hasZeroCapability({ network: ['example.com'], filesystem: [], credentials: [] })).toBe(
      false,
    );
  });

  it('is false when at least one filesystem prefix is granted', () => {
    expect(
      hasZeroCapability({ network: false, filesystem: ['./workspace'], credentials: [] }),
    ).toBe(false);
  });

  it('is false when at least one credential is granted', () => {
    expect(
      hasZeroCapability({ network: false, filesystem: [], credentials: ['.aws/credentials'] }),
    ).toBe(false);
  });

  it('is true for an empty network allowlist plus no filesystem/credentials', () => {
    expect(hasZeroCapability({ network: [], filesystem: [], credentials: [] })).toBe(true);
  });
});
