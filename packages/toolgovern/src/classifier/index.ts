/**
 * The classifier: runs every rule in the TG01-TG05 pack against one normalized call context and
 * aggregates the result. Decision severity order is `deny` > `require-approval` > `allow` -- if
 * any rule denies, the call is denied, no matter how many other rules would have allowed it.
 *
 * Every non-allow decision is traceable to the specific rule ID(s) that fired and the argument
 * that tripped each one -- see `types.ts#RuleMatch`. There is no unexplained black-box denial in
 * this classifier: if `firedRules` is empty, the decision is (and can only be) `allow`.
 */

import type { AsyncRule, ClassifierResult, Decision, RuleContext, RuleMatch } from '../types.js';
import { shellRiskRules } from './shell-risk.js';
import { filesystemScopeRules } from './filesystem-scope.js';
import { networkEgressRules, networkEgressAsyncRules } from './network-egress.js';
import { credentialAccessRules } from './credential-access.js';
import { crossAgentInheritanceRules } from './cross-agent-inheritance.js';

export const ruleRegistry = [
  ...shellRiskRules,
  ...filesystemScopeRules,
  ...networkEgressRules,
  ...credentialAccessRules,
  ...crossAgentInheritanceRules,
];

/** Every registered `AsyncRule` -- currently just TG03's DNS-resolution check. Evaluated only by
 *  `classifyAsync()`, never by the synchronous `classify()`. See `types.ts#AsyncRule`. */
export const asyncRuleRegistry: readonly AsyncRule[] = [...networkEgressAsyncRules];

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

function applyDowngrade(result: RuleMatch, downgrade: ReadonlySet<string>): RuleMatch {
  return result.decision === 'deny' && downgrade.has(result.ruleId)
    ? { ...result, decision: 'require-approval' }
    : result;
}

function aggregateDecision(firedRules: readonly RuleMatch[]): Decision {
  return firedRules.reduce<Decision>(
    (acc, r) => (severity(r.decision) > severity(acc) ? r.decision : acc),
    'allow',
  );
}

/** Evaluates one tool call against every enabled *synchronous* rule and returns the aggregate
 *  verdict. Does not run `asyncRuleRegistry` (TG03's DNS-resolution check) -- a caller that can
 *  `await` should use `classifyAsync()` instead so that check is not silently skipped. This
 *  function stays synchronous, unchanged, for callers with no event loop to await from. */
export function classify(ctx: RuleContext, options: ClassifyOptions = {}): ClassifierResult {
  const disabled = new Set(options.disabledRules ?? []);
  const downgrade = new Set(options.downgradeToApproval ?? []);

  const firedRules: RuleMatch[] = [];
  for (const rule of ruleRegistry) {
    if (disabled.has(rule.id)) continue;
    const result = rule.evaluate(ctx);
    if (!result) continue;
    firedRules.push(applyDowngrade(result, downgrade));
  }

  return { decision: aggregateDecision(firedRules), firedRules };
}

/**
 * Async counterpart to `classify()`. Runs every synchronous rule exactly as `classify()` does,
 * then awaits every registered `AsyncRule` (currently just TG03's `TG03-dns-resolves-private`
 * DNS-resolution check) and folds its verdict into the same aggregate, at the same `deny` >
 * `require-approval` > `allow` severity ordering. `governTool()`'s `execute()` -- already async
 * end-to-end -- calls this instead of `classify()` so a hostname argument that *resolves* to a
 * private/loopback/cloud-metadata address is caught, not just a raw IP literal argument. Any
 * other integration point that can `await` should prefer this over `classify()` for the same
 * reason.
 */
export async function classifyAsync(
  ctx: RuleContext,
  options: ClassifyOptions = {},
): Promise<ClassifierResult> {
  const disabled = new Set(options.disabledRules ?? []);
  const downgrade = new Set(options.downgradeToApproval ?? []);

  const firedRules: RuleMatch[] = [];
  for (const rule of ruleRegistry) {
    if (disabled.has(rule.id)) continue;
    const result = rule.evaluate(ctx);
    if (!result) continue;
    firedRules.push(applyDowngrade(result, downgrade));
  }

  for (const rule of asyncRuleRegistry) {
    if (disabled.has(rule.id)) continue;
    const result = await rule.evaluateAsync(ctx);
    if (!result) continue;
    firedRules.push(applyDowngrade(result, downgrade));
  }

  return { decision: aggregateDecision(firedRules), firedRules };
}

export {
  shellRiskRules,
  filesystemScopeRules,
  networkEgressRules,
  networkEgressAsyncRules,
  credentialAccessRules,
  crossAgentInheritanceRules,
};
