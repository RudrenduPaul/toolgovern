/**
 * Loads and validates a `toolgovern.policy.yml` file from disk.
 *
 *     const policy = loadPolicy('./toolgovern.policy.yml')
 *     const gatedShellTool = governTool(shellTool, policy)
 *
 * `loadPolicy` is synchronous by design -- it is meant to run once at process startup, the same
 * way a framework loads any other config file, and callers should not have to `await` it just to
 * wrap a tool definition.
 */

import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import type { Policy } from '../types.js';
import { asPolicy, validatePolicy } from './validatePolicy.js';

export class PolicyValidationError extends Error {
  constructor(
    filePath: string,
    public readonly errors: readonly string[],
  ) {
    super(`Invalid policy file "${filePath}":\n${errors.map((e) => `  - ${e}`).join('\n')}`);
    this.name = 'PolicyValidationError';
  }
}

/** Parses and validates a policy file, throwing `PolicyValidationError` if it is invalid. */
export function loadPolicy(filePath: string): Policy {
  const raw = readFileSync(filePath, 'utf8');
  let parsed: unknown;
  try {
    parsed = parse(raw);
  } catch (cause) {
    throw new Error(`Failed to parse policy file "${filePath}" as YAML.`, { cause });
  }

  const result = validatePolicy(parsed);
  if (!result.valid) {
    throw new PolicyValidationError(filePath, result.errors);
  }
  return asPolicy(parsed);
}
