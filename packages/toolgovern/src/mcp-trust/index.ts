/**
 * MCP-server trust boundary: connection-time governance of the MCP *servers* an agent connects
 * to, as distinct from TG01-TG05's per-call classification of what a tool call does once a
 * server is already connected and its tools are already being invoked.
 *
 * This is a categorically different governance moment. TG01-TG05 (`classifier/index.ts`) all run
 * *after* an MCP server's tools are already trusted and being called -- they evaluate one call's
 * arguments against a declared scope. Nothing in that pipeline ever asks "should this agent have
 * connected to this MCP server, and trusted the tool definitions it declared, in the first
 * place?" This module answers exactly that question, once, at connection time, before any tool
 * call from that server is ever classified.
 *
 * Motivated by two real 2026 MCP supply-chain incidents (see `docs/security-model.md`,
 * "MCP-server trust boundary" for the fuller writeup this module resolves):
 *
 * - The CrewAI CVE-2026-2275/2287 chain, where the trust path between the agent runtime and an
 *   untrusted MCP-sourced tool was the enabling condition for a prompt-injection-to-RCE chain.
 * - The Postmark MCP package rug-pull, where a previously-trusted MCP server pushed a malicious
 *   update and every downstream deployment inherited it, because nothing pinned or verified what
 *   the server was allowed to declare.
 *
 * Two primitives, and a deliberate fail-closed posture on both:
 *
 * 1. `isOriginAllowed()` -- an explicit origin allowlist, checked once per connection, not once
 *    per call. No implicit subdomain trust: an allowlist entry matches only that exact origin
 *    unless the operator explicitly opts into subdomain matching with a leading `*.` entry.
 * 2. `verifyMcpServerManifest()` -- signature verification of a fetched MCP server manifest
 *    against a pinned public-key list before any tool the manifest declares is ever trusted.
 *    Supports Ed25519 and RSA-SHA256 detached signatures over the manifest's exact bytes. There
 *    is no code path in this module that returns `'allow'` without a signature that actually
 *    verified against a pinned key -- an unreachable manifest, an unknown key ID, a signature
 *    that fails to verify, and an unconfigured pinned-key list all deny, they do not warn.
 *
 * What this explicitly does NOT do, disclosed rather than hidden:
 *
 * - No sigstore/keyless verification (transparency-log-backed, no pinned key list to manage) --
 *   the pinned-key path is the one this module actually implements and tests; a keyless flow is
 *   a real, separate feature with its own trust model (Rekor log verification, Fulcio certificate
 *   chain validation, OIDC identity binding) that is not attempted here.
 * - No revocation checking for a pinned key that has been compromised or retired -- pinning a key
 *   here means the operator has (and rotates) that list themselves; there is no CRL/OCSP-style
 *   revocation lookup.
 * - No re-verification of a live connection after the manifest check passes -- this is a
 *   connection-time gate, run once before a server's tools are trusted. It does not re-check the
 *   manifest on every subsequent tool call from that server (TG01-TG05 remain responsible for
 *   what each individual call actually does).
 * - `isOriginAllowed()`'s allowlist match is a plain string/hostname comparison, not a TLS
 *   certificate or transport-identity check -- it decides whether an asserted origin string is on
 *   the allowlist, the same caller-asserted-string caveat `docs/security-model.md` already
 *   documents for `agentId`.
 */

import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { normalizeHost } from '../shared/paths.js';

/** MCP-server trust decisions are binary and fail-closed -- there is no `'require-approval'`
 *  third state here, unlike the per-call `Decision` type in `types.ts`. A connection either
 *  passed every connection-time check, or it did not; there is no human-in-the-loop step at
 *  connection time in this v0.1 (a caller wanting one can treat `'deny'` as "route to an approval
 *  flow" in their own integration, but this module itself only ever returns one of these two). */
export type McpTrustDecision = 'allow' | 'deny';

/** A pinned public key an MCP server manifest's detached signature is checked against.
 *  `algorithm` fixes what verification scheme applies to `publicKeyPem` -- there is no
 *  algorithm-sniffing from the key material itself, so a caller cannot smuggle in an unexpected
 *  scheme by mislabeling a key. */
export interface PinnedPublicKey {
  /** Identifier a signed manifest's envelope must reference so verification knows which pinned
   *  key to check the signature against. Free-form, but must match exactly (case-sensitive). */
  readonly keyId: string;
  readonly algorithm: 'ed25519' | 'rsa-sha256';
  /** SPKI PEM-encoded public key, e.g. the output of
   *  `crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' })`. */
  readonly publicKeyPem: string;
}

/** The exact, already-fetched (or directly-supplied) manifest signature envelope
 *  `verifyMcpServerManifest()` verifies. `manifestBytes` must be the literal bytes the signer
 *  signed -- this module never re-serializes a parsed manifest object before verifying, since
 *  re-serialization is not guaranteed byte-stable and would make a genuinely valid signature
 *  appear to fail (or, worse, make verification pass against a payload the signer never actually
 *  signed). */
export interface McpManifestEnvelope {
  readonly manifestBytes: string;
  /** Base64-encoded detached signature over `manifestBytes` (UTF-8 encoded). */
  readonly signatureB64: string;
  /** Which `PinnedPublicKey.keyId` this signature claims to be from. */
  readonly keyId: string;
}

/** Options for `verifyMcpServerManifest()`. */
export interface VerifyManifestOptions {
  /** The pinned public-key list a manifest's signature must verify against. An empty list is a
   *  hard misconfiguration, not "trust everything" -- `verifyMcpServerManifest()` denies rather
   *  than silently skipping verification. */
  readonly pinnedKeys: readonly PinnedPublicKey[];
  /** Injectable fetch implementation, primarily for tests. Defaults to `globalThis.fetch`. */
  readonly fetchImpl?: typeof fetch;
  /** Hard timeout for fetching a manifest URL. A hung/unresponsive manifest host must not be able
   *  to stall a connection attempt indefinitely -- exactly the same rationale `network-egress.ts`
   *  already applies to its own DNS-lookup timeout. */
  readonly timeoutMs?: number;
}

/** The outcome of an MCP-server trust check. `decision` is never a silent `'allow'` produced by
 *  an unhandled edge case -- every deny carries a human-readable `reason` explaining exactly
 *  which check failed, mirroring `RuleMatch.reason` in `types.ts`. */
export interface McpTrustVerdict {
  readonly decision: McpTrustDecision;
  readonly reason: string;
}

/** One MCP-server connection attempt: the origin the agent is about to connect to, and the URL
 *  (or an already-fetched envelope) of that server's manifest. */
export interface McpServerConnectionRequest {
  readonly origin: string;
  readonly manifest: string | McpManifestEnvelope;
}

/** The full connection-time trust policy: an origin allowlist plus a pinned-key list for
 *  manifest-signature verification. Passed to `assertMcpServerTrusted()`. */
export interface McpTrustPolicy {
  readonly allowedOrigins: readonly string[];
  readonly pinnedKeys: readonly PinnedPublicKey[];
  readonly fetchImpl?: typeof fetch;
  readonly timeoutMs?: number;
}

/**
 * Checked once at MCP-server CONNECTION time, never per-call -- an explicit allowlist of the
 * origins an agent is permitted to connect to at all.
 *
 * Default posture is exact match, not subdomain trust: an allowlist entry of `"example.com"`
 * matches `"example.com"` only, not `"evil.example.com"`. An operator who genuinely wants
 * subdomain matching opts in explicitly with a leading `*.` entry (`"*.example.com"` matches
 * `"example.com"` and any subdomain of it). This is a deliberate divergence from TG03's
 * `hostMatchesAllowed()` (which matches subdomains unconditionally) -- a connection-time server
 * allowlist is a narrower, higher-stakes trust decision than a per-call network-egress check, and
 * defaulting to the broader match here would silently grant trust to any attacker-registered
 * subdomain of an allowed domain the operator never actually considered.
 *
 * `origin` and each allowlist entry may be a full origin (`"https://mcp.example.com"`) or a bare
 * hostname (`"mcp.example.com"`) -- both are normalized to a hostname before comparison. Returns
 * `false` (never throws) for an empty or unparseable origin, or an empty allowlist -- an empty
 * allowlist is "nothing is allowed," not "anything is allowed."
 */
export function isOriginAllowed(origin: string, allowlist: readonly string[]): boolean {
  if (!origin || allowlist.length === 0) return false;
  const host = normalizeHost(origin);
  if (!host) return false;

  return allowlist.some((rawEntry) => {
    const entry = rawEntry.trim();
    if (entry.length === 0) return false;
    if (entry.startsWith('*.')) {
      const suffix = entry.slice(2).toLowerCase();
      if (suffix.length === 0) return false;
      return host === suffix || host.endsWith(`.${suffix}`);
    }
    const entryHost = normalizeHost(entry);
    return entryHost.length > 0 && host === entryHost;
  });
}

/** Verifies a detached signature over `data` using `publicKeyPem`, per `algorithm`. Ed25519 uses
 *  Node's `null`-algorithm PureEdDSA `crypto.verify()` form; RSA uses SHA-256 digest signing
 *  (PKCS#1 v1.5 padding, `crypto.verify()`'s default for an RSA key). Throws only if
 *  `publicKeyPem` itself is not parseable as a public key -- an actual signature mismatch returns
 *  `false`, it does not throw. */
function verifySignatureBytes(
  algorithm: PinnedPublicKey['algorithm'],
  publicKeyPem: string,
  data: Buffer,
  signature: Buffer,
): boolean {
  const publicKey = createPublicKey(publicKeyPem);
  if (algorithm === 'ed25519') {
    return cryptoVerify(null, data, publicKey, signature);
  }
  return cryptoVerify('sha256', data, publicKey, signature);
}

/** The shape a manifest URL's JSON response body must have. Deliberately minimal and explicit:
 *  `manifest` is the literal signed string, never an object this module would need to
 *  re-serialize (see `McpManifestEnvelope`'s doc comment for why that distinction matters). */
interface ManifestEnvelopeResponseBody {
  readonly manifest?: unknown;
  readonly signature?: unknown;
  readonly keyId?: unknown;
}

const DEFAULT_MANIFEST_FETCH_TIMEOUT_MS = 5_000;

async function fetchManifestEnvelope(
  manifestUrl: string,
  opts: Pick<VerifyManifestOptions, 'fetchImpl' | 'timeoutMs'>,
): Promise<McpManifestEnvelope> {
  const fetchFn = opts.fetchImpl ?? globalThis.fetch;
  if (!fetchFn) {
    throw new Error(
      'No fetch implementation available: globalThis.fetch is undefined and no fetchImpl was supplied.',
    );
  }
  const timeoutMs = opts.timeoutMs ?? DEFAULT_MANIFEST_FETCH_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response: Response;
  try {
    response = await fetchFn(manifestUrl, { signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
  if (!response.ok) {
    throw new Error(`Manifest fetch returned HTTP ${response.status} ${response.statusText}`);
  }
  const body = (await response.json()) as ManifestEnvelopeResponseBody;
  if (
    typeof body.manifest !== 'string' ||
    typeof body.signature !== 'string' ||
    typeof body.keyId !== 'string'
  ) {
    throw new Error(
      'Manifest response is missing one or more required fields (manifest, signature, keyId) ' +
        'or a field is not a string.',
    );
  }
  return { manifestBytes: body.manifest, signatureB64: body.signature, keyId: body.keyId };
}

/**
 * Verifies an MCP server manifest's detached signature against a pinned public-key list before
 * any tool the manifest declares may be trusted. Accepts either a manifest URL (fetched, subject
 * to `opts.timeoutMs`) or an already-fetched `McpManifestEnvelope` directly (for callers that
 * fetched it themselves, or for tests that want to skip the network entirely).
 *
 * Fail-closed on every path, never a silent allow:
 *
 * - No pinned keys configured -> `deny` (an empty pinned-key list is a misconfiguration to catch
 *   loudly, not "verification is optional").
 * - Manifest URL unreachable, times out, or returns a non-2xx/malformed response -> `deny`.
 * - Envelope's `keyId` does not match any pinned key -> `deny`.
 * - Signature or manifest bytes are malformed (undecodable base64, etc.) -> `deny`.
 * - Signature verification throws (a malformed pinned public key, for instance) -> `deny`.
 * - Signature does not verify against the matched pinned key -> `deny`. This includes a
 *   bit-flipped/tampered manifest with its original (now-mismatched) signature left in place --
 *   flipping even a single byte of `manifestBytes` changes what the signature must verify
 *   against, so a genuine Ed25519/RSA signature over the original bytes will not verify over the
 *   tampered ones. See `test/mcp-trust/index.test.ts`'s "tampered manifest" case for a direct
 *   proof of this, not just an assertion of it.
 * - Only a signature that positively verifies against a pinned key returns `allow`.
 */
export async function verifyMcpServerManifest(
  manifestUrlOrEnvelope: string | McpManifestEnvelope,
  opts: VerifyManifestOptions,
): Promise<McpTrustVerdict> {
  if (opts.pinnedKeys.length === 0) {
    return {
      decision: 'deny',
      reason:
        'No pinned public keys configured -- refusing to trust any manifest signature (fail closed).',
    };
  }

  let envelope: McpManifestEnvelope;
  if (typeof manifestUrlOrEnvelope === 'string') {
    try {
      envelope = await fetchManifestEnvelope(manifestUrlOrEnvelope, opts);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        decision: 'deny',
        reason: `Manifest unreachable at "${manifestUrlOrEnvelope}": ${message}. Failing closed.`,
      };
    }
  } else {
    envelope = manifestUrlOrEnvelope;
  }

  const key = opts.pinnedKeys.find((candidate) => candidate.keyId === envelope.keyId);
  if (!key) {
    return {
      decision: 'deny',
      reason: `Manifest signed with keyId "${envelope.keyId}", which is not in the pinned key list. Failing closed.`,
    };
  }

  let signatureBytes: Buffer;
  let dataBytes: Buffer;
  try {
    signatureBytes = Buffer.from(envelope.signatureB64, 'base64');
    if (signatureBytes.length === 0) {
      throw new Error('decoded signature is empty');
    }
    dataBytes = Buffer.from(envelope.manifestBytes, 'utf8');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      decision: 'deny',
      reason: `Malformed manifest signature encoding: ${message}. Failing closed.`,
    };
  }

  let verified: boolean;
  try {
    verified = verifySignatureBytes(key.algorithm, key.publicKeyPem, dataBytes, signatureBytes);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      decision: 'deny',
      reason: `Signature verification against pinned key "${key.keyId}" threw (${message}) -- treating as unverified. Failing closed.`,
    };
  }

  if (!verified) {
    return {
      decision: 'deny',
      reason: `Manifest signature does not verify against pinned key "${key.keyId}". Failing closed.`,
    };
  }

  return {
    decision: 'allow',
    reason: `Manifest signature verified against pinned key "${key.keyId}" (${key.algorithm}).`,
  };
}

/**
 * The single connection-time gate combining both primitives: an MCP server's tools are trusted
 * only if its origin is on the allowlist AND its manifest's signature verifies against a pinned
 * key. Either check failing alone is a hard deny -- there is no partial-trust state, and origin
 * is checked first so a manifest fetch (network I/O) is never attempted for an origin that was
 * never going to be trusted anyway.
 */
export async function assertMcpServerTrusted(
  request: McpServerConnectionRequest,
  policy: McpTrustPolicy,
): Promise<McpTrustVerdict> {
  if (!isOriginAllowed(request.origin, policy.allowedOrigins)) {
    return {
      decision: 'deny',
      reason: `Origin "${request.origin}" is not on the connection-time allowlist. Failing closed.`,
    };
  }
  return verifyMcpServerManifest(request.manifest, {
    pinnedKeys: policy.pinnedKeys,
    fetchImpl: policy.fetchImpl,
    timeoutMs: policy.timeoutMs,
  });
}
