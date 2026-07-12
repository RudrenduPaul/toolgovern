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
  isPrivateOrMetadataTarget as sharedIsPrivateOrMetadataTarget,
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

/** Extracts the raw `code` string argument a code-execution tool (Python/Node/shell interpreter
 *  "run this code" style tool) was invoked with, if any. Kept separate from `extractCommand`
 *  (which also looks at `code` among other keys) so path/operation inference below can scan the
 *  code body specifically without depending on which other command-like key happened to win. */
export function extractCodeText(args: Readonly<Record<string, unknown>>): string | undefined {
  const value = args['code'];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/** The first string-literal argument to a common file-open/read/write/delete call inside a code
 *  string (Python `open(...)`, Node `fs.readFile(...)`/`fs.writeFileSync(...)`, `os.remove(...)`,
 *  `shutil.rmtree(...)`, ...) is treated as a candidate filesystem path. */
const CODE_FILE_CALL_PATTERN =
  /\b(?:open|readfile|readfilesync|writefile|writefilesync|unlink|unlinksync|rmsync|rmdirsync|chmod|chown|chmodsync|chownsync|os\.remove|os\.unlink|os\.rmdir|os\.chmod|os\.chown|fs\.chmod|fs\.chown|shutil\.rmtree|shutil\.copy\w*)\s*\(\s*["']([^"']+)["']/i;

/** A bare `../`-traversal or absolute-path string literal anywhere in a code string, even outside
 *  a recognized file-open call (e.g. a path assembled via a variable but still containing a
 *  literal traversal fragment quoted on its own). Used only when no recognized call matched. */
const CODE_BARE_PATH_PATTERN = /["'`]((?:\.\.\/)+[^"'`]*|\/(?:[\w.-]+\/)*[\w.-]+)["'`]/;

/** Scans a code-execution tool's `code` string for a path-like literal. Closes the gap where a
 *  path-traversal payload (or any other write/delete/chmod target) is embedded inside a `code`
 *  argument rather than passed under a `path`/`target`/`dest`-style key -- e.g. Python code
 *  containing `open("../../etc/passwd")` handed to a generic "run this code" tool. */
export function extractPathFromCode(code: string): string | undefined {
  const callMatch = code.match(CODE_FILE_CALL_PATTERN);
  if (callMatch?.[1]) return callMatch[1];
  const bareMatch = code.match(CODE_BARE_PATH_PATTERN);
  if (bareMatch?.[1]) return bareMatch[1];
  return undefined;
}

/** Recognized delete/chmod/write call shapes inside a code string, used to infer an operation
 *  when the tool call has no explicit `operation`/`op`/`action`/`mode` argument -- only the code
 *  itself reveals what the embedded path is actually used for. */
const CODE_DELETE_PATTERN =
  /\b(?:os\.remove|os\.unlink|os\.rmdir|shutil\.rmtree|fs\.unlink|fs\.unlinksync|fs\.rm|fs\.rmsync|fs\.rmdir|fs\.rmdirsync|unlinksync|rmsync|rmdirsync)\s*\(/i;
const CODE_CHMOD_PATTERN =
  /\b(?:os\.chmod|os\.chown|fs\.chmod|fs\.chmodsync|fs\.chown|fs\.chownsync|chmodsync|chownsync)\s*\(/i;
const CODE_WRITE_CALL_PATTERN =
  /\b(?:writefile|writefilesync|fs\.writefile|fs\.writefilesync|os\.write)\s*\(/i;
/** Python's `open(path, mode)` -- any mode containing w/a/x (write/append/exclusive-create) is a
 *  write; a bare `open(path)` or explicit `"r"` mode is a read, which this does not classify. */
const CODE_OPEN_WRITE_MODE_PATTERN = /\bopen\s*\([^)]*?,\s*["'](\w*[wax]\w*)["']/i;

/** Infers a write/delete/chmod operation from a code string's recognized call shapes. Returns
 *  `undefined` (not "read") when nothing recognizable matched -- callers fall back to their own
 *  read-vs-unknown handling. */
export function extractOperationFromCode(code: string): string | undefined {
  if (CODE_DELETE_PATTERN.test(code)) return 'delete';
  if (CODE_CHMOD_PATTERN.test(code)) return 'chmod';
  if (CODE_WRITE_CALL_PATTERN.test(code) || CODE_OPEN_WRITE_MODE_PATTERN.test(code)) {
    return 'write';
  }
  return undefined;
}

/** Extracts a filesystem-path-like string from common argument key names, falling back to
 *  scanning a `code` string argument (see `extractPathFromCode`) when no `path`/`target`/`dest`-
 *  style key is present. */
export function extractPath(args: Readonly<Record<string, unknown>>): string | undefined {
  const direct = firstString(args, PATH_KEYS);
  if (direct) return direct;
  const code = extractCodeText(args);
  return code ? extractPathFromCode(code) : undefined;
}

/** Extracts a declared filesystem operation (read/write/delete/chmod/...) if the tool provides
 *  one, falling back to inferring one from a `code` string argument (see
 *  `extractOperationFromCode`) when no `operation`/`op`/`action`/`mode` key is present. */
export function extractOperation(args: Readonly<Record<string, unknown>>): string | undefined {
  const direct = firstString(args, OPERATION_KEYS)?.toLowerCase();
  if (direct) return direct;
  const code = extractCodeText(args);
  return code ? extractOperationFromCode(code) : undefined;
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

/** True if `host` is a raw IP literal, IPv4 or IPv6 (not a domain name). */
export const isIpLiteral = sharedIsIpLiteral;

/** True if `host` targets loopback, an RFC1918/unique-local private range, link-local space, or
 *  a cloud-metadata endpoint -- see `shared/paths.ts#isPrivateOrMetadataTarget` for the full
 *  range list. */
export const isPrivateOrMetadataTarget = sharedIsPrivateOrMetadataTarget;

/** Maximum object/array nesting depth `findNestedHost` will descend into. Bounds the search
 *  against pathological or cyclic-looking (self-referential arrays are still finite in JSON, but
 *  deeply/absurdly nested) argument payloads. */
const MAX_HOST_SEARCH_DEPTH = 8;

/** Depth-first search for the first `HOST_KEYS`-named string value anywhere inside a nested
 *  argument bag, so a host/URL buried inside a nested payload (e.g. an MCP tool call's nested
 *  `params.target.url`) is still found rather than only checked at the top level. */
function findNestedHost(value: unknown, depth = 0): string | undefined {
  if (value == null || depth > MAX_HOST_SEARCH_DEPTH) return undefined;

  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findNestedHost(item, depth + 1);
      if (found) return found;
    }
    return undefined;
  }

  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const direct = firstString(record, HOST_KEYS);
    if (direct) return direct;
    for (const nested of Object.values(record)) {
      if (nested != null && typeof nested === 'object') {
        const found = findNestedHost(nested, depth + 1);
        if (found) return found;
      }
    }
  }

  return undefined;
}

/**
 * Pulls a candidate network host out of an explicit host/url argument -- checked at the top
 * level first, then recursively through nested objects/arrays so a host buried inside a nested
 * tool-call payload isn't missed -- or otherwise scans a shell-command-like string for the first
 * `http(s)://` URL. Returns a normalized hostname.
 */
export function extractCandidateHost(args: Readonly<Record<string, unknown>>): string | undefined {
  const explicit = extractHost(args) ?? findNestedHost(args);
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
