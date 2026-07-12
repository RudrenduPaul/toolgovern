/**
 * Helpers for validating and comparing `ScopeDeclaration` values.
 *
 * A `ScopeDeclaration` is intentionally simple: an agent gets access to what it declares, and
 * nothing else. There is no implicit "and everything under this is fine too" beyond the explicit
 * path-prefix / hostname-suffix / credential-identifier matching implemented here.
 */

import type { ScopeDeclaration } from '../types.js';

/** The empty scope: no network, no filesystem, no credentials. This is the default-deny floor. */
export const EMPTY_SCOPE: ScopeDeclaration = {
  network: false,
  filesystem: [],
  credentials: [],
};

export function isValidScopeDeclaration(value: unknown): value is ScopeDeclaration {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Record<string, unknown>;

  const networkOk =
    typeof candidate.network === 'boolean' ||
    (Array.isArray(candidate.network) && candidate.network.every((h) => typeof h === 'string'));
  const filesystemOk =
    Array.isArray(candidate.filesystem) && candidate.filesystem.every((p) => typeof p === 'string');
  const credentialsOk =
    Array.isArray(candidate.credentials) &&
    candidate.credentials.every((c) => typeof c === 'string');

  return networkOk && filesystemOk && credentialsOk;
}

/** Normalizes a partial/loosely-typed scope object into a fully-formed `ScopeDeclaration`,
 *  defaulting any missing field to the most restrictive value (default-deny). */
export function normalizeScope(partial: Partial<ScopeDeclaration> | undefined): ScopeDeclaration {
  return {
    network: partial?.network ?? false,
    filesystem: partial?.filesystem ?? [],
    credentials: partial?.credentials ?? [],
  };
}

/** Generous ceiling on `agentId` length. Not a protocol limit -- just large enough that no
 *  realistic identity scheme (UUID, DNS name, URN, JWT `sub` claim) trips it, while still
 *  rejecting unbounded strings that look like a buffer-abuse or log-flooding attempt. */
const MAX_AGENT_ID_LENGTH = 256;

/** Code points with no legitimate reason to appear in an agent identity string: ASCII control
 *  characters (0x00-0x1F, 0x7F) and the Unicode line/paragraph separators (0x2028, 0x2029).
 *  Letting them through invites log-injection (an embedded newline forging what looks like an
 *  extra trace line), null-byte truncation tricks against downstream C-string comparisons, or
 *  terminal/ANSI escape abuse in anything that later prints `agentId` to a console. Checked via
 *  explicit code-unit ranges (not a regex) so the ranges are unambiguous in source and don't trip
 *  lint rules that (rightly) flag raw control characters inside regex literals. */
function isDisallowedControlCodeUnit(codeUnit: number): boolean {
  return (
    (codeUnit >= 0x00 && codeUnit <= 0x1f) ||
    codeUnit === 0x7f ||
    codeUnit === 0x2028 ||
    codeUnit === 0x2029
  );
}

/**
 * Format-only validation for an `agentId` string.
 *
 * IMPORTANT -- what this is NOT: this does not verify that a caller actually is the agent it
 * claims to be. toolgovern has no cryptographic identity verification mechanism in v0.1; any
 * caller can still supply any well-formed `agentId` and have it accepted as-is (see
 * `docs/security-model.md`). A string that passes `isValidAgentId` is merely *well-formed* -- it
 * remains just as much a bare, unverified claim as any other string that passes.
 *
 * What this DOES do: reject a narrow, concrete class of malformed/malicious inputs that should
 * never be treated as a valid identity at all, regardless of whether identity is ever
 * cryptographically checked -- an empty string, a string past a sane length ceiling, or a string
 * containing control characters/embedded null bytes that could be used for log injection or to
 * confuse downstream string handling. This is a hygiene filter, not an authentication mechanism.
 */
export function isValidAgentId(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  if (value.length === 0) return false;
  if (value.length > MAX_AGENT_ID_LENGTH) return false;
  for (let i = 0; i < value.length; i += 1) {
    if (isDisallowedControlCodeUnit(value.charCodeAt(i))) return false;
  }
  return true;
}
