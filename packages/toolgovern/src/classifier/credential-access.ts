/**
 * TG04 -- Credential/Secret Access
 *
 * Fires when a call reads `.env`, `.ssh`, `.aws/credentials`, OS keychain entries, or dumps the
 * bulk process environment, and that resource is not present in the caller's declared
 * credential scope.
 */

import type { Rule, RuleContext, RuleMatch } from '../types.js';
import {
  extractCommand,
  extractCredentialName,
  extractPath,
  isCredentialGranted,
  normalizeForMatch,
  stringifyArgs,
} from './util.js';

const category = 'TG04' as const;

function match(
  rule: Pick<Rule, 'id' | 'category'>,
  decision: RuleMatch['decision'],
  reason: string,
  matchedArgument: string,
): RuleMatch {
  return { ruleId: rule.id, category: rule.category, decision, reason, matchedArgument };
}

/** `text` is normalized (see `normalizeForMatch`) before pattern matching, so the same
 *  quote-splitting / `$IFS` / invisible-Unicode tricks that could dodge TG01's shell patterns
 *  cannot be used to dodge these credential-path patterns either. `path`, when present, is left
 *  as-is: it feeds a declared-scope allowlist membership check, not a regex match, so
 *  obfuscation-normalization semantics do not apply to it the same way. */
function pathOrCommandText(ctx: RuleContext): { path: string | undefined; text: string } {
  const path = extractPath(ctx.args);
  const text = normalizeForMatch(
    path ?? extractCommand(ctx.args) ?? stringifyArgs(ctx.args),
  ).toLowerCase();
  return { path, text };
}

const dotenvAccess: Rule = {
  id: 'TG04-dotenv-access',
  category,
  description: 'Access to a .env-style file outside the declared credential scope.',
  evaluate(ctx) {
    const { path, text } = pathOrCommandText(ctx);
    const found = text.match(/(^|[/\s])\.env(\.\w+)?\b/);
    if (!found) return null;
    const identifier = path ?? found[0].trim();
    if (isCredentialGranted(identifier, ctx.scope.credentials)) return null;
    return match(
      this,
      'deny',
      `Access to ".env" file "${identifier}" not in declared credential scope.`,
      identifier,
    );
  },
};

const sshKeyAccess: Rule = {
  id: 'TG04-ssh-key-access',
  category,
  description: 'Access to a private SSH key or the .ssh directory.',
  evaluate(ctx) {
    const { path, text } = pathOrCommandText(ctx);
    const found = text.match(/\.ssh\/(id_\w+|config|authorized_keys)?/);
    if (!found) return null;
    const identifier = path ?? found[0];
    if (isCredentialGranted(identifier, ctx.scope.credentials)) return null;
    return match(
      this,
      'deny',
      `Access to SSH credential material "${identifier}" not in declared credential scope.`,
      identifier,
    );
  },
};

const cloudCredentialFile: Rule = {
  id: 'TG04-cloud-credential-file',
  category,
  description: 'Access to a cloud provider credential/config file.',
  evaluate(ctx) {
    const { path, text } = pathOrCommandText(ctx);
    const found = text.match(
      /\.(aws\/(credentials|config)|gcp\/[\w.-]+|azure\/[\w.-]+|kube\/config)/,
    );
    if (!found) return null;
    const identifier = path ?? found[0];
    if (isCredentialGranted(identifier, ctx.scope.credentials)) return null;
    return match(
      this,
      'deny',
      `Access to cloud credential file "${identifier}" not in declared credential scope.`,
      identifier,
    );
  },
};

const keychainAccess: Rule = {
  id: 'TG04-keychain-access',
  category,
  description: 'Access to an OS-level keychain/secret store.',
  evaluate(ctx) {
    const text = normalizeForMatch(
      extractCommand(ctx.args) ?? stringifyArgs(ctx.args),
    ).toLowerCase();
    const found = text.match(/(security\s+find-generic-password|secret-tool\s+lookup|keytar)/);
    if (!found) return null;
    return match(this, 'deny', 'Access to OS keychain/secret-store credential material.', found[0]);
  },
};

const bulkEnvDump: Rule = {
  id: 'TG04-bulk-env-dump',
  category,
  description: 'Unfiltered dump of the full process environment.',
  evaluate(ctx) {
    const text = normalizeForMatch(extractCommand(ctx.args) ?? '')
      .toLowerCase()
      .trim();
    const found = text.match(/^(env|printenv|export\s+-p)\s*$/);
    if (!found) return null;
    return match(this, 'require-approval', 'Bulk, unfiltered process-environment dump.', found[0]);
  },
};

const credentialNameNotInScope: Rule = {
  id: 'TG04-credential-name-not-in-scope',
  category,
  description: 'An explicitly named credential/secret argument is not in the declared scope.',
  evaluate(ctx) {
    const name = extractCredentialName(ctx.args);
    if (!name) return null;
    if (isCredentialGranted(name, ctx.scope.credentials)) return null;
    return match(
      this,
      'deny',
      `Credential "${name}" is not in the declared credential scope.`,
      name,
    );
  },
};

export const credentialAccessRules: readonly Rule[] = [
  dotenvAccess,
  sshKeyAccess,
  cloudCredentialFile,
  keychainAccess,
  bulkEnvDump,
  credentialNameNotInScope,
];
