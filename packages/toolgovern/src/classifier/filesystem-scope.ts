/**
 * TG02 -- Filesystem Scope Escalation
 *
 * Fires when a call attempts a write, delete, or permission change outside the caller's
 * declared filesystem scope (`scope.filesystem`, a list of allowed path prefixes), or targets a
 * small set of sensitive absolute system directories regardless of scope.
 */

import type { Rule, RuleMatch } from '../types.js';
import { containsPathTraversal, extractOperation, extractPath, isPathWithin } from './util.js';

const category = 'TG02' as const;

const WRITE_OPS = new Set(['write', 'create', 'append', 'put', 'save']);
const DELETE_OPS = new Set(['delete', 'remove', 'unlink', 'rm', 'rmdir']);
const CHMOD_OPS = new Set(['chmod', 'chown', 'setpermissions', 'set_permissions']);
const READ_OPS = new Set(['read', 'get', 'load', 'fetch', 'cat', 'open']);
const SENSITIVE_SYSTEM_PREFIXES = ['/etc', '/usr', '/bin', '/sbin', '/system', '/private/etc'];

function isWithinScope(path: string, filesystem: readonly string[]): boolean {
  if (filesystem.length === 0) return false;
  return filesystem.some((prefix) => isPathWithin(path, prefix));
}

function match(
  rule: Pick<Rule, 'id' | 'category'>,
  decision: RuleMatch['decision'],
  reason: string,
  matchedArgument: string,
): RuleMatch {
  return { ruleId: rule.id, category: rule.category, decision, reason, matchedArgument };
}

const writeOutsideScope: Rule = {
  id: 'TG02-write-outside-scope',
  category,
  description: 'A write/create targets a path outside the declared filesystem scope.',
  evaluate(ctx) {
    const path = extractPath(ctx.args);
    if (!path) return null;
    const op =
      extractOperation(ctx.args) ?? (ctx.tool.toLowerCase().includes('write') ? 'write' : '');
    if (!WRITE_OPS.has(op)) return null;
    if (isWithinScope(path, ctx.scope.filesystem)) return null;
    return match(
      this,
      'require-approval',
      `Write target "${path}" is outside the declared filesystem scope.`,
      path,
    );
  },
};

const deleteOutsideScope: Rule = {
  id: 'TG02-delete-outside-scope',
  category,
  description: 'A delete targets a path outside the declared filesystem scope.',
  evaluate(ctx) {
    const path = extractPath(ctx.args);
    if (!path) return null;
    const op =
      extractOperation(ctx.args) ?? (ctx.tool.toLowerCase().includes('delete') ? 'delete' : '');
    if (!DELETE_OPS.has(op)) return null;
    if (isWithinScope(path, ctx.scope.filesystem)) return null;
    return match(
      this,
      'deny',
      `Delete target "${path}" is outside the declared filesystem scope.`,
      path,
    );
  },
};

const chmodOutsideScope: Rule = {
  id: 'TG02-chmod-outside-scope',
  category,
  description: 'A permission change targets a path outside the declared filesystem scope.',
  evaluate(ctx) {
    const path = extractPath(ctx.args);
    if (!path) return null;
    const op = extractOperation(ctx.args);
    if (!op || !CHMOD_OPS.has(op)) return null;
    if (isWithinScope(path, ctx.scope.filesystem)) return null;
    return match(
      this,
      'deny',
      `Permission change on "${path}" is outside the declared filesystem scope.`,
      path,
    );
  },
};

const readOutsideScope: Rule = {
  id: 'TG02-read-outside-scope',
  category,
  description:
    "A read targets a path outside the caller's declared filesystem scope. Only fires when a " +
    'filesystem boundary was actually declared -- reads are not flagged for a caller with no ' +
    'declared filesystem scope at all (that absence is enforced elsewhere, e.g. TG05 zero-' +
    'capability denial), since nothing here would tell a read apart from any other unscoped call.',
  evaluate(ctx) {
    if (ctx.scope.filesystem.length === 0) return null;
    const path = extractPath(ctx.args);
    if (!path) return null;
    const op =
      extractOperation(ctx.args) ?? (ctx.tool.toLowerCase().includes('read') ? 'read' : '');
    if (!READ_OPS.has(op)) return null;
    if (isWithinScope(path, ctx.scope.filesystem)) return null;
    return match(
      this,
      'require-approval',
      `Read target "${path}" is outside the declared filesystem scope.`,
      path,
    );
  },
};

const pathTraversal: Rule = {
  id: 'TG02-path-traversal',
  category,
  description: 'A path uses ".." segments that could escape a scoped prefix.',
  evaluate(ctx) {
    const path = extractPath(ctx.args);
    if (!path) return null;
    if (!containsPathTraversal(path)) return null;
    return match(this, 'deny', `Path "${path}" contains traversal segments ("..").`, path);
  },
};

const symlinkEscape: Rule = {
  id: 'TG02-symlink-escape',
  category,
  description: 'A symlink/link operation targets a path outside the declared filesystem scope.',
  evaluate(ctx) {
    const op = extractOperation(ctx.args) ?? '';
    if (!/symlink|link/.test(op)) return null;
    const path = extractPath(ctx.args);
    if (!path) return null;
    if (isWithinScope(path, ctx.scope.filesystem)) return null;
    return match(
      this,
      'deny',
      `Symlink target "${path}" is outside the declared filesystem scope.`,
      path,
    );
  },
};

const sensitiveSystemPath: Rule = {
  id: 'TG02-sensitive-system-path',
  category,
  description: 'A write/delete targets a sensitive absolute system directory.',
  evaluate(ctx) {
    const path = extractPath(ctx.args);
    if (!path) return null;
    const op = extractOperation(ctx.args) ?? '';
    if (!WRITE_OPS.has(op) && !DELETE_OPS.has(op) && !CHMOD_OPS.has(op)) return null;
    const lower = path.toLowerCase();
    const hit = SENSITIVE_SYSTEM_PREFIXES.find((prefix) => lower.startsWith(prefix));
    if (!hit) return null;
    return match(
      this,
      'deny',
      `Target "${path}" is under a sensitive system directory (${hit}).`,
      path,
    );
  },
};

export const filesystemScopeRules: readonly Rule[] = [
  writeOutsideScope,
  deleteOutsideScope,
  chmodOutsideScope,
  readOutsideScope,
  pathTraversal,
  symlinkEscape,
  sensitiveSystemPath,
];
