/**
 * The classifier: runs every rule in the TG01-TG05 pack against one normalized call context and
 * aggregates the result. Decision severity order is `deny` > `require-approval` > `allow` -- if
 * any rule denies, the call is denied, no matter how many other rules would have allowed it.
 *
 * Every non-allow decision is traceable to the specific rule ID(s) that fired and the argument
 * that tripped each one -- see `types.ts#RuleMatch`. There is no unexplained black-box denial in
 * this classifier: if `firedRules` is empty, the decision is (and can only be) `allow`.
 */

import type { ClassifierResult, Decision, RuleContext, RuleMatch } from '../types.js';
import { shellRiskRules } from './shell-risk.js';
import { filesystemScopeRules } from './filesystem-scope.js';
import { networkEgressRules } from './network-egress.js';
import { credentialAccessRules } from './credential-access.js';
import { crossAgentInheritanceRules } from './cross-agent-inheritance.js';

export const ruleRegistry = [
  ...shellRiskRules,
  ...filesystemScopeRules,
  ...networkEgressRules,
  ...credentialAccessRules,
  ...crossAgentInheritanceRules,
];

export interface ClassifyOptions {
  /** Rule IDs to skip entirely regardless of arguments (from `Policy.rules.disable`). */
  readonly disabledRules?: readonly string[];
  /** Rule IDs whose `deny` verdict should be downgraded to `require-approval`
   *  (from `Policy.rules.requireApproval`). */
  readonly downgradeToApproval?: readonly string[];
}

function severity(decision: Decision): number {
  switch (decision) {
    case 'deny':
      return 2;
    case 'require-approval':
      return 1;
    default:
      return 0;
  }
}

/** Evaluates one tool call against every enabled rule and returns the aggregate verdict. */
export function classify(ctx: RuleContext, options: ClassifyOptions = {}): ClassifierResult {
  const disabled = new Set(options.disabledRules ?? []);
  const downgrade = new Set(options.downgradeToApproval ?? []);

  const firedRules: RuleMatch[] = [];
  for (const rule of ruleRegistry) {
    if (disabled.has(rule.id)) continue;
    const result = rule.evaluate(ctx);
    if (!result) continue;
    if (result.decision === 'deny' && downgrade.has(rule.id)) {
      firedRules.push({ ...result, decision: 'require-approval' });
    } else {
      firedRules.push(result);
    }
  }

  const decision = firedRules.reduce<Decision>(
    (acc, r) => (severity(r.decision) > severity(acc) ? r.decision : acc),
    'allow',
  );

  return { decision, firedRules };
}

export {
  shellRiskRules,
  filesystemScopeRules,
  networkEgressRules,
  credentialAccessRules,
  crossAgentInheritanceRules,
};
