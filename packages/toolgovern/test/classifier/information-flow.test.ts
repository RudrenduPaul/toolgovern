import { describe, expect, it } from 'vitest';
import { informationFlowRules } from '../../src/classifier/information-flow.js';
import type { IfcPolicy, RuleContext } from '../../src/types.js';

const RULE_ID = 'TG08-confidential-source-to-untrusted-sink';

function rule() {
  const found = informationFlowRules.find((r) => r.id === RULE_ID);
  if (!found) throw new Error(`No such rule: ${RULE_ID}`);
  return found;
}

function ctx(args: Record<string, unknown>, ifc: IfcPolicy | undefined = undefined): RuleContext {
  return {
    agentId: 'agent-1',
    sessionId: 'session-1',
    tool: 'data.transfer',
    args,
    scope: { network: false, filesystem: [], credentials: [], ifc },
  };
}

const CUSTOMER_DB_CONFIDENTIAL: IfcPolicy = {
  sources: { 'db.customers': 'confidential' },
  sinkTrust: { 'internal.dashboard': 'confidential', 'public.webhook': 'public' },
};

describe('TG08 information-flow control', () => {
  it('does not fire when no IFC policy is declared at all (opt-in)', () => {
    const result = rule().evaluate(
      ctx({ source: 'db.customers', to: 'public.webhook' }, undefined),
    );
    expect(result).toBeNull();
  });

  it('does not fire when the call has no recognized source argument', () => {
    const result = rule().evaluate(
      ctx({ query: 'select * from customers', to: 'public.webhook' }, CUSTOMER_DB_CONFIDENTIAL),
    );
    expect(result).toBeNull();
  });

  it('does not fire when the source is not labeled at all', () => {
    const result = rule().evaluate(
      ctx({ source: 'db.public_prices', to: 'public.webhook' }, CUSTOMER_DB_CONFIDENTIAL),
    );
    expect(result).toBeNull();
  });

  it('does not fire when the source is labeled public', () => {
    const policy: IfcPolicy = {
      sources: { 'db.marketing': 'public' },
      sinkTrust: {},
    };
    const result = rule().evaluate(ctx({ source: 'db.marketing', to: 'public.webhook' }, policy));
    expect(result).toBeNull();
  });

  it('does not fire when a confidential source has no sink argument at all', () => {
    // A pure read with nothing declared as a destination is not a flow this rule can (or should)
    // evaluate -- there is nothing to compare the source's label against.
    const result = rule().evaluate(ctx({ source: 'db.customers' }, CUSTOMER_DB_CONFIDENTIAL));
    expect(result).toBeNull();
  });

  it('allows when the sink is declared trusted at or above the source label', () => {
    const result = rule().evaluate(
      ctx({ source: 'db.customers', to: 'internal.dashboard' }, CUSTOMER_DB_CONFIDENTIAL),
    );
    expect(result).toBeNull();
  });

  it('denies when the declared sink trust is explicitly lower than the source label', () => {
    const result = rule().evaluate(
      ctx({ source: 'db.customers', to: 'public.webhook' }, CUSTOMER_DB_CONFIDENTIAL),
    );
    expect(result).not.toBeNull();
    expect(result?.decision).toBe('deny');
    expect(result?.ruleId).toBe(RULE_ID);
    expect(result?.matchedArgument).toBe('public.webhook');
  });

  it('fails closed to require-approval when the sink trust tier is not declared at all', () => {
    const result = rule().evaluate(
      ctx({ source: 'db.customers', to: 'unknown.third-party.example' }, CUSTOMER_DB_CONFIDENTIAL),
    );
    expect(result).not.toBeNull();
    expect(result?.decision).toBe('require-approval');
    expect(result?.matchedArgument).toBe('unknown.third-party.example');
  });

  it('matches source/sink identifiers via trailing-segment and substring, like isCredentialGranted', () => {
    const policy: IfcPolicy = {
      sources: { customers: 'restricted' },
      sinkTrust: { dashboard: 'restricted' },
    };
    const result = rule().evaluate(
      ctx({ source: 'db.prod.customers', to: 'internal.dashboard' }, policy),
    );
    expect(result).toBeNull();
  });

  it('recognizes alternate declared source/sink argument key names', () => {
    const result = rule().evaluate(
      ctx({ from: 'db.customers', destination: 'public.webhook' }, CUSTOMER_DB_CONFIDENTIAL),
    );
    expect(result?.decision).toBe('deny');
  });

  it('ranks restricted above confidential -- a confidential-only sink cannot receive restricted data', () => {
    const policy: IfcPolicy = {
      sources: { 'db.secrets': 'restricted' },
      sinkTrust: { 'internal.dashboard': 'confidential' },
    };
    const result = rule().evaluate(ctx({ source: 'db.secrets', to: 'internal.dashboard' }, policy));
    expect(result?.decision).toBe('deny');
  });
});
