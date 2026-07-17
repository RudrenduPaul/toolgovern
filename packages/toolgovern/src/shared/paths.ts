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
  // A bracketed IPv6 literal (`[::1]` or `[::1]:8080`) -- unwrap the brackets and drop any
  // trailing port, but keep the address itself intact.
  const bracketed = withoutPath.match(/^\[([^\]]+)\]/);
  if (bracketed) {
    return (bracketed[1] ?? '').toLowerCase();
  }
  // A bare host containing more than one colon is an IPv6 literal, not a `host:port` pair --
  // splitting on the first colon (as below) would truncate the address.
  if ((withoutPath.match(/:/g) ?? []).length >= 2) {
    return withoutPath.toLowerCase();
  }
  const withoutPort = withoutPath.split(':')[0] ?? withoutPath;
  return withoutPort.toLowerCase();
}

/** True if `host` is a dotted-decimal IPv4 literal (`a.b.c.d`), and only that form -- used
 *  where a bare decimal integer must NOT be treated as an IP (parsing an IPv6 literal's
 *  hextets, where a plain numeric group like `1234` in `fe80::1234` is ordinary hex, not a
 *  packed IPv4 address). `parseIpv4Octets` below is the looser, general-purpose check. */
function isDottedIpv4Literal(host: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
}

/** Parses `host` as an IPv4 address in either dotted-decimal (`a.b.c.d`) or bare
 *  single-integer decimal form (the same address packed into one 32-bit unsigned integer,
 *  e.g. `2852039166` for `169.254.169.254`) -- the latter is accepted as a valid IP literal
 *  by curl, browsers, and most OS resolvers, and is a well-known technique for slipping a
 *  private/metadata target past a dotted-decimal-only IP-literal check. Returns the four
 *  octets, or `null` if `host` is neither form. */
function parseIpv4Octets(host: string): [number, number, number, number] | null {
  if (isDottedIpv4Literal(host)) {
    const octets = host.split('.').map(Number);
    if (octets.length !== 4 || octets.some((o) => Number.isNaN(o) || o > 255)) return null;
    return octets as [number, number, number, number];
  }
  if (/^\d{1,10}$/.test(host)) {
    const value = Number(host);
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) return null;
    return [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff];
  }
  return null;
}

/** True if `host` is a raw IPv4 literal (not a domain name), dotted-decimal or bare
 *  single-integer decimal form (see `parseIpv4Octets`). */
function isIpv4Literal(host: string): boolean {
  return parseIpv4Octets(host) !== null;
}

/** Strips an optional surrounding `[...]` bracket pair and a trailing `%zone` scope id from an
 *  IPv6 literal, e.g. `[fe80::1%eth0]` -> `fe80::1`. */
function stripIpv6Decoration(host: string): string {
  let h = host.trim();
  const bracketed = h.match(/^\[([^\]]+)\]$/);
  if (bracketed) h = bracketed[1] ?? '';
  const zoneIndex = h.indexOf('%');
  if (zoneIndex !== -1) h = h.slice(0, zoneIndex);
  return h;
}

/** Parses a bare (undecorated) IPv6 literal into its eight 16-bit groups, expanding a single
 *  `::` run and an embedded IPv4 tail (e.g. `::ffff:169.254.169.254`). Returns `null` if `host`
 *  is not a syntactically valid IPv6 literal. */
function parseIpv6Groups(host: string): number[] | null {
  if (!host.includes(':')) return null;
  const hasDoubleColon = host.includes('::');
  if ((host.match(/::/g) ?? []).length > 1) return null;

  let head = host;
  let tail = '';
  if (hasDoubleColon) {
    const parts = host.split('::');
    if (parts.length !== 2) return null;
    head = parts[0] ?? '';
    tail = parts[1] ?? '';
  }

  const hextetPattern = /^[0-9a-f]{1,4}$/i;
  const splitHextets = (segment: string): string[] =>
    segment.length === 0 ? [] : segment.split(':');
  const headParts = splitHextets(head);
  const tailParts = splitHextets(tail);

  // An embedded IPv4 tail (`::ffff:169.254.169.254`) contributes two hextets worth of bits.
  let embeddedIpv4: number[] | null = null;
  const lastTailPart = tailParts[tailParts.length - 1];
  if (lastTailPart && isDottedIpv4Literal(lastTailPart)) {
    const octets = lastTailPart.split('.').map(Number);
    if (octets.length !== 4 || octets.some((o) => Number.isNaN(o) || o > 255)) return null;
    const [o0, o1, o2, o3] = octets as [number, number, number, number];
    embeddedIpv4 = [(o0 << 8) | o1, (o2 << 8) | o3];
    tailParts.pop();
  }

  if (headParts.some((p) => !hextetPattern.test(p))) return null;
  if (tailParts.some((p) => !hextetPattern.test(p))) return null;

  const headGroups = headParts.map((p) => parseInt(p, 16));
  const tailGroups = tailParts.map((p) => parseInt(p, 16));
  const embeddedLength = embeddedIpv4 ? 2 : 0;
  const total = headGroups.length + tailGroups.length + embeddedLength;

  let groups: number[];
  if (hasDoubleColon) {
    const zeros = 8 - total;
    if (zeros < 0) return null;
    groups = [...headGroups, ...new Array(zeros).fill(0), ...tailGroups, ...(embeddedIpv4 ?? [])];
  } else {
    if (total !== 8) return null;
    groups = [...headGroups, ...tailGroups, ...(embeddedIpv4 ?? [])];
  }
  return groups.length === 8 ? groups : null;
}

/** True if `host` is a raw IPv6 literal -- bracketed or bare, with or without a `%zone` id or an
 *  embedded IPv4 tail. */
function isIpv6Literal(host: string): boolean {
  return parseIpv6Groups(stripIpv6Decoration(host)) !== null;
}

/** True if `host` is a raw IP literal, IPv4 or IPv6 (not a domain name). */
export function isIpLiteral(host: string): boolean {
  return isIpv4Literal(host) || isIpv6Literal(host);
}

/** True if IPv4 `octets` fall in a loopback, RFC1918-private, or link-local range -- link-local
 *  (`169.254.0.0/16`) includes the `169.254.169.254` cloud-metadata endpoint used by AWS, GCP,
 *  Azure, and most other cloud providers. */
function isPrivateIpv4Octets(octets: readonly [number, number, number, number]): boolean {
  const [a, b] = octets;
  if (a === 127) return true; // loopback 127.0.0.0/8
  if (a === 10) return true; // RFC1918 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918 172.16.0.0/12
  if (a === 192 && b === 168) return true; // RFC1918 192.168.0.0/16
  if (a === 169 && b === 254) return true; // link-local, incl. cloud metadata 169.254.169.254
  return false;
}

/** True if `host` is a raw IP literal (v4 or v6) that targets loopback, an RFC1918/unique-local
 *  private range, link-local space, or a cloud-metadata endpoint (`169.254.169.254` and its
 *  IPv6 equivalents: `::1`, `fe80::/10`, `fc00::/7`, and IPv4-mapped `::ffff:a.b.c.d` addresses
 *  that resolve into one of the above IPv4 ranges) -- the set of destinations a rubber-stamped
 *  human approval should never be able to wave through. */
export function isPrivateOrMetadataTarget(host: string): boolean {
  const ipv4Octets = parseIpv4Octets(host);
  if (ipv4Octets) {
    return isPrivateIpv4Octets(ipv4Octets);
  }

  const groups = parseIpv6Groups(stripIpv6Decoration(host));
  if (!groups) return false;
  const [g0, g1, g2, g3, g4, g5, g6, g7] = groups as [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
  ];

  // ::1 loopback
  if (
    g0 === 0 &&
    g1 === 0 &&
    g2 === 0 &&
    g3 === 0 &&
    g4 === 0 &&
    g5 === 0 &&
    g6 === 0 &&
    g7 === 1
  ) {
    return true;
  }
  // fe80::/10 link-local
  if ((g0 & 0xffc0) === 0xfe80) return true;
  // fc00::/7 unique-local
  if ((g0 & 0xfe00) === 0xfc00) return true;
  // IPv4-mapped (::ffff:a.b.c.d) -- check the embedded IPv4 address
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0xffff) {
    const octets: [number, number, number, number] = [g6 >> 8, g6 & 0xff, g7 >> 8, g7 & 0xff];
    return isPrivateIpv4Octets(octets);
  }
  return false;
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
