/**
 * Low-level path/host normalization helpers shared by the classifier and the scoping registry.
 * Kept dependency-free and side-effect-free so both modules can import from here without a
 * classifier <-> scoping cycle.
 */

/** Collapses `./`, trailing slashes, and duplicate slashes for stable prefix comparison. */
export function normalizePath(rawPath: string): string {
  let path = rawPath.trim();
  if (path.startsWith('./')) {
    path = path.slice(2);
  }
  path = path.replace(/\/+/g, '/');
  if (path.length > 1 && path.endsWith('/')) {
    path = path.slice(0, -1);
  }
  return path;
}

/** True if `candidate` is equal to, or a path-segment child of, `prefix`. */
export function isPathWithin(candidate: string, prefix: string): boolean {
  const normalizedCandidate = normalizePath(candidate);
  const normalizedPrefix = normalizePath(prefix);
  if (normalizedPrefix === '' || normalizedPrefix === '.') {
    return true;
  }
  return (
    normalizedCandidate === normalizedPrefix ||
    normalizedCandidate.startsWith(`${normalizedPrefix}/`)
  );
}

/** True if the path contains a `..` segment that could escape a scoped prefix via traversal. */
export function containsPathTraversal(rawPath: string): boolean {
  return rawPath.split('/').includes('..');
}

/** Best-effort hostname extraction from a bare host string or a full URL. */
export function normalizeHost(hostLike: string): string {
  const trimmed = hostLike.trim();
  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
      return new URL(trimmed).hostname.toLowerCase();
    }
  } catch {
    // fall through to the raw-string heuristics below
  }
  const withoutPath = trimmed.split('/')[0] ?? trimmed;
  const withoutPort = withoutPath.split(':')[0] ?? withoutPath;
  return withoutPort.toLowerCase();
}

/** True if `host` is a raw IPv4 literal (not a domain name). */
export function isIpLiteral(host: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
}

/** True if `host` matches `allowed` exactly or is a subdomain of it. */
export function hostMatchesAllowed(host: string, allowed: string): boolean {
  const h = host.toLowerCase();
  const a = allowed.toLowerCase();
  return h === a || h.endsWith(`.${a}`);
}

/** True if `identifier` matches `granted` exactly, as a path suffix, or as a substring -- used
 *  for credential-identifier comparisons where declared scopes are often coarse-grained
 *  (e.g. granting `"aws"` should cover `".aws/credentials"`). */
export function credentialMatchesGranted(identifier: string, granted: string): boolean {
  const i = identifier.toLowerCase();
  const g = granted.toLowerCase();
  return i === g || i.endsWith(`/${g}`) || i.includes(g);
}
