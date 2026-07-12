/**
 * Shared argument-extraction helpers for rule implementations.
 *
 * Real tool-call argument shapes vary a lot across frameworks -- a shell tool might name its
 * argument `command`, `cmd`, or `script`. Rather than force every framework to normalize to one
 * schema before toolgovern can evaluate a call, each rule looks for a small set of common key
 * names and falls back to scanning the stringified argument bag. This is deliberately permissive
 * (a false negative here is worse than a rare false positive from the string fallback).
 */

import {
  containsPathTraversal as sharedContainsPathTraversal,
  isIpLiteral as sharedIsIpLiteral,
  isPathWithin as sharedIsPathWithin,
  normalizeHost as sharedNormalizeHost,
  normalizePath as sharedNormalizePath,
} from '../shared/paths.js';

const COMMAND_KEYS = ['command', 'cmd', 'script', 'shell', 'code'];
const PATH_KEYS = ['path', 'target', 'dest', 'destination', 'file', 'filepath', 'file_path'];
const OPERATION_KEYS = ['operation', 'op', 'action', 'mode'];
const HOST_KEYS = ['host', 'hostname', 'url', 'uri', 'endpoint', 'address'];
const CREDENTIAL_KEYS = ['credential', 'secret', 'secretName', 'credentialId'];

function firstString(
  args: Readonly<Record<string, unknown>>,
  keys: readonly string[],
): string | undefined {
  for (const key of keys) {
    const value = args[key];
    if (typeof value === 'string' && value.length > 0) {
      return value;
    }
  }
  return undefined;
}

/** Extracts a shell-command-like string from common argument key names. */
export function extractCommand(args: Readonly<Record<string, unknown>>): string | undefined {
  return firstString(args, COMMAND_KEYS);
}

/** Extracts a filesystem-path-like string from common argument key names. */
export function extractPath(args: Readonly<Record<string, unknown>>): string | undefined {
  return firstString(args, PATH_KEYS);
}

/** Extracts a declared filesystem operation (read/write/delete/chmod/...) if the tool provides one. */
export function extractOperation(args: Readonly<Record<string, unknown>>): string | undefined {
  return firstString(args, OPERATION_KEYS)?.toLowerCase();
}

/** Extracts a network host/URL-like string from common argument key names. */
export function extractHost(args: Readonly<Record<string, unknown>>): string | undefined {
  return firstString(args, HOST_KEYS);
}

/** Extracts a declared credential identifier from common argument key names. */
export function extractCredentialName(args: Readonly<Record<string, unknown>>): string | undefined {
  return firstString(args, CREDENTIAL_KEYS);
}

/**
 * Flattens every string value in the argument bag into one lowercase blob, used as a fallback
 * scan target for pattern rules (e.g. shell-injection patterns) when no known key name matches.
 */
export function stringifyArgs(args: Readonly<Record<string, unknown>>): string {
  const parts: string[] = [];
  for (const value of Object.values(args)) {
    if (typeof value === 'string') {
      parts.push(value);
    } else if (value != null && typeof value !== 'object') {
      parts.push(String(value));
    }
  }
  return parts.join(' ').toLowerCase();
}

/** Zero-width, bidi-control, and other invisible-format Unicode characters sometimes inserted
 *  mid-token to break a literal-substring or `\b` word-boundary match (e.g. `sudo` with a
 *  zero-width space spliced in). Stripped before pattern matching, never before execution.
 *  Ranges (by escape, not pasted glyph, so the intent is unambiguous in source and diffs):
 *  U+00AD soft hyphen, U+200B-200F zero-width space/joiners/marks, U+202A-202E bidi
 *  embedding/override controls, U+2060-2064 word joiner/invisible operators, U+FEFF BOM. */
const INVISIBLE_FORMAT_CHARS = new RegExp(
  '[\\u00AD\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\uFEFF]',
  'g',
);

/** `$IFS` / `${IFS}` (optionally with a positional-parameter suffix like `$9`) is a well-known
 *  shell field-separator substitution attackers use in place of a literal space specifically to
 *  dodge whitespace-based pattern matching, without changing what the shell actually executes. */
const IFS_SEPARATOR = /\$\{?IFS\}?(\$\d+)?/gi;

/** An adjacent pair of matching quote characters (`''` or `""`) contributes nothing to what a
 *  POSIX shell actually runs -- `r""m -rf /` and `rm -rf /` execute identically -- but it does
 *  break a naive literal-substring match against `rm`. Collapsed here, repeatedly, so stacked
 *  pairs (`r""""m`) are fully removed. */
function collapseEmptyQuotePairs(text: string): string {
  let current = text;
  let previous: string;
  do {
    previous = current;
    current = current.replace(/(['"])\1/g, '');
  } while (current !== previous);
  return current;
}

/**
 * Normalizes free-form command/argument text before it is matched against a classifier pattern.
 * This does not change what actually gets executed -- it only closes the gap between "what the
 * shell will run" and "what a literal regex sees" for a handful of well-known obfuscation tricks:
 * Unicode confusables/invisible characters, `$IFS`-as-space substitution, and empty-quote-pair
 * token splitting (`cu''rl`, `r""m`). It intentionally does not attempt full shell-grammar
 * parsing -- see `docs/security-model.md` for what obfuscation shapes remain out of scope for a
 * regex-based, per-call classifier.
 */
export function normalizeForMatch(text: string): string {
  let normalized = text.normalize('NFKC');
  normalized = normalized.replace(INVISIBLE_FORMAT_CHARS, '');
  normalized = normalized.replace(IFS_SEPARATOR, ' ');
  normalized = collapseEmptyQuotePairs(normalized);
  normalized = normalized.replace(/\\([A-Za-z0-9])/g, '$1');
  return normalized;
}

/** Best-effort hostname extraction from a bare host string or a full URL. Re-exported from
 *  `shared/paths.ts` so existing rule imports keep working. */
export const normalizeHost = sharedNormalizeHost;

/** True if `candidate` is equal to, or a path-segment child of, `prefix`. */
export const isPathWithin = sharedIsPathWithin;

/** Collapses `./`, trailing slashes, and duplicate slashes for stable prefix comparison. */
export const normalizePath = sharedNormalizePath;

/** True if the path contains a `..` segment that could escape a scoped prefix via traversal. */
export const containsPathTraversal = sharedContainsPathTraversal;

/** True if `host` is a raw IPv4 literal (not a domain name). */
export const isIpLiteral = sharedIsIpLiteral;

/**
 * Pulls a candidate network host out of an explicit host/url argument, or otherwise scans a
 * shell-command-like string for the first `http(s)://` URL. Returns a normalized hostname.
 */
export function extractCandidateHost(args: Readonly<Record<string, unknown>>): string | undefined {
  const explicit = extractHost(args);
  if (explicit) return sharedNormalizeHost(normalizeForMatch(explicit));

  const command = normalizeForMatch(extractCommand(args) ?? stringifyArgs(args));
  const urlMatch = command.match(/https?:\/\/[^\s"'|]+/i);
  if (urlMatch) return sharedNormalizeHost(urlMatch[0]);
  return undefined;
}

/** Extracts whichever resource identifier a credential-scoped call is targeting -- an explicit
 *  credential/secret name if the tool provides one, otherwise the filesystem path. */
export function extractCredentialIdentifier(
  args: Readonly<Record<string, unknown>>,
): string | undefined {
  return extractCredentialName(args) ?? extractPath(args);
}
