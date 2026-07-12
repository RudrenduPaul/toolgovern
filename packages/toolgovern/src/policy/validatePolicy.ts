/**
 * Structural and rule-reference validation for a policy file. Used both by `loadPolicy()`
 * (throws on failure -- a program should not start with a broken policy) and by
 * `toolgovern-cli validate` (reports every error found, without throwing, so a developer gets
 * one full list instead of fixing errors one at a time).
 */

import type { Policy } from '../types.js';
import { isValidScopeDeclaration } from '../scoping/scope-declaration.js';
import { ruleRegistry } from '../classifier/index.js';

export interface PolicyValidationResult {
  readonly valid: boolean;
  readonly errors: readonly string[];
}

const VALID_RULE_IDS = new Set(ruleRegistry.map((r) => r.id));
const VALID_DECISIONS = new Set(['allow', 'deny', 'require-approval']);

/** Validates a parsed (but untyped) policy object. Returns every error found, not just the first. */
export function validatePolicy(raw: unknown): PolicyValidationResult {
  const errors: string[] = [];

  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return { valid: false, errors: ['Policy file must define a single YAML mapping (object).'] };
  }
  const candidate = raw as Record<string, unknown>;

  if (candidate.name !== undefined && typeof candidate.name !== 'string') {
    errors.push('"name" must be a string if present.');
  }
  if (candidate.policy !== undefined && typeof candidate.policy !== 'string') {
    errors.push('"policy" must be a string if present.');
  }

  if (!isValidScopeDeclaration(candidate.scope)) {
    errors.push(
      '"scope" is required and must have network (boolean or string[]), filesystem (string[]), and credentials (string[]).',
    );
  }

  if (candidate.defaultDecision !== undefined) {
    if (
      typeof candidate.defaultDecision !== 'string' ||
      !VALID_DECISIONS.has(candidate.defaultDecision)
    ) {
      errors.push('"defaultDecision" must be one of: allow, deny, require-approval.');
    }
  }

  if (candidate.rules !== undefined) {
    if (typeof candidate.rules !== 'object' || candidate.rules === null) {
      errors.push(
        '"rules" must be an object with optional "disable" and "requireApproval" arrays.',
      );
    } else {
      const rules = candidate.rules as Record<string, unknown>;
      for (const field of ['disable', 'requireApproval'] as const) {
        const value = rules[field];
        if (value === undefined) continue;
        if (!Array.isArray(value) || !value.every((id) => typeof id === 'string')) {
          errors.push(`"rules.${field}" must be an array of rule ID strings.`);
          continue;
        }
        for (const ruleId of value as string[]) {
          if (!VALID_RULE_IDS.has(ruleId)) {
            errors.push(
              `"rules.${field}" references unknown rule ID "${ruleId}". Valid rule IDs: ${[...VALID_RULE_IDS].join(', ')}.`,
            );
          }
        }
      }
    }
  }

  return { valid: errors.length === 0, errors };
}

/** Narrows `raw` to `Policy` after `validatePolicy` has confirmed it is structurally valid. */
export function asPolicy(raw: unknown): Policy {
  return raw as Policy;
}
