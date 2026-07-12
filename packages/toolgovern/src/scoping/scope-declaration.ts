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
