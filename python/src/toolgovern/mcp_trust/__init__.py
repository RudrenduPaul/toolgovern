"""MCP-server trust boundary: connection-time governance of the MCP *servers* an agent connects
to, as distinct from TG01-TG05's per-call classification of what a tool call does once a server
is already connected and its tools are already being invoked.

Ported from ``packages/toolgovern/src/mcp-trust/index.ts``. See that module's docstring for the
full rationale (the CrewAI CVE-2026-2275/2287 chain and the Postmark MCP rug-pull); this port
mirrors its two primitives and its fail-closed behavior exactly, with one deliberate,
disclosed asymmetry: this port fetches a manifest URL synchronously via ``urllib.request``
(``govern_tool()`` is synchronous end-to-end in this port, same rationale as TG03's
``socket.getaddrinfo()`` use), where the TS original uses ``fetch()``. Same checks, same
fail-closed outcomes, different (language-appropriate) I/O plumbing.

Two primitives, and a deliberate fail-closed posture on both:

1. ``is_origin_allowed()`` -- an explicit origin allowlist, checked once per connection, not once
   per call. No implicit subdomain trust: an allowlist entry matches only that exact origin
   unless the operator explicitly opts into subdomain matching with a leading ``*.`` entry.
2. ``verify_mcp_server_manifest()`` -- signature verification of a fetched MCP server manifest
   against a pinned public-key list before any tool the manifest declares is ever trusted.
   Supports Ed25519 and RSA-SHA256 (PKCS#1 v1.5) detached signatures over the manifest's exact
   bytes, via the ``cryptography`` package. There is no code path in this module that returns
   ``"allow"`` without a signature that actually verified against a pinned key -- an unreachable
   manifest, an unknown key ID, a signature that fails to verify, and an unconfigured pinned-key
   list all deny, they do not warn.

What this explicitly does NOT do, disclosed rather than hidden:

- No sigstore/keyless verification -- the pinned-key path is the one this module actually
  implements and tests.
- No revocation checking for a pinned key that has been compromised or retired.
- No re-verification of a live connection after the manifest check passes -- this is a
  connection-time gate, run once before a server's tools are trusted.
- ``is_origin_allowed()``'s allowlist match is a plain string/hostname comparison, not a TLS
  certificate or transport-identity check.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Literal, Optional, Sequence, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from ..shared.paths import normalize_host

# MCP-server trust decisions are binary and fail-closed -- there is no "require-approval" third
# state here, unlike the per-call Decision type in types.py. A connection either passed every
# connection-time check, or it did not.
McpTrustDecision = Literal["allow", "deny"]

Algorithm = Literal["ed25519", "rsa-sha256"]

#: Injectable fetch function: given a manifest URL and a timeout (seconds), returns the raw
#: response bytes, or raises on any failure (connection error, non-2xx status, timeout). Real
#: callers get ``_default_fetch`` (``urllib.request``); tests inject a stand-in.
FetchImpl = Callable[[str, float], bytes]

DEFAULT_MANIFEST_FETCH_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class PinnedPublicKey:
    """A pinned public key an MCP server manifest's detached signature is checked against.
    ``algorithm`` fixes what verification scheme applies to ``public_key_pem`` -- there is no
    algorithm-sniffing from the key material itself."""

    key_id: str
    algorithm: Algorithm
    public_key_pem: str


@dataclass(frozen=True)
class McpManifestEnvelope:
    """The exact, already-fetched (or directly-supplied) manifest signature envelope
    ``verify_mcp_server_manifest()`` verifies. ``manifest_bytes`` must be the literal bytes the
    signer signed -- this module never re-serializes a parsed manifest object before verifying."""

    manifest_bytes: str
    signature_b64: str
    key_id: str


@dataclass(frozen=True)
class McpTrustVerdict:
    """The outcome of an MCP-server trust check. ``decision`` is never a silent "allow" produced
    by an unhandled edge case -- every deny carries a human-readable ``reason``."""

    decision: McpTrustDecision
    reason: str


@dataclass(frozen=True)
class McpServerConnectionRequest:
    """One MCP-server connection attempt: the origin the agent is about to connect to, and the
    URL (or an already-fetched envelope) of that server's manifest."""

    origin: str
    manifest: Union[str, McpManifestEnvelope]


@dataclass(frozen=True)
class McpTrustPolicy:
    """The full connection-time trust policy: an origin allowlist plus a pinned-key list for
    manifest-signature verification. Passed to ``assert_mcp_server_trusted()``."""

    allowed_origins: Sequence[str]
    pinned_keys: Sequence[PinnedPublicKey]
    fetch_impl: Optional[FetchImpl] = None
    timeout_seconds: float = DEFAULT_MANIFEST_FETCH_TIMEOUT_SECONDS


def is_origin_allowed(origin: str, allowlist: Sequence[str]) -> bool:
    """Checked once at MCP-server CONNECTION time, never per-call -- an explicit allowlist of
    the origins an agent is permitted to connect to at all.

    Default posture is exact match, not subdomain trust: an allowlist entry of ``"example.com"``
    matches ``"example.com"`` only, not ``"evil.example.com"``. An operator who genuinely wants
    subdomain matching opts in explicitly with a leading ``*.`` entry (``"*.example.com"``
    matches ``"example.com"`` and any subdomain of it). This deliberately diverges from TG03's
    ``host_matches_allowed()`` (which matches subdomains unconditionally) -- a connection-time
    server allowlist is a narrower, higher-stakes trust decision than a per-call network-egress
    check.

    ``origin`` and each allowlist entry may be a full origin (``"https://mcp.example.com"``) or a
    bare hostname (``"mcp.example.com"``) -- both are normalized to a hostname before comparison.
    Returns ``False`` (never raises) for an empty/unparseable origin or an empty allowlist -- an
    empty allowlist is "nothing is allowed," not "anything is allowed."
    """
    if not origin or not allowlist:
        return False
    host = normalize_host(origin)
    if not host:
        return False

    def _matches(raw_entry: str) -> bool:
        entry = raw_entry.strip()
        if not entry:
            return False
        if entry.startswith("*."):
            suffix = entry[2:].lower()
            if not suffix:
                return False
            return host == suffix or host.endswith(f".{suffix}")
        entry_host = normalize_host(entry)
        return bool(entry_host) and host == entry_host

    return any(_matches(entry) for entry in allowlist)


def _verify_signature_bytes(
    algorithm: Algorithm, public_key_pem: str, data: bytes, signature: bytes
) -> bool:
    """Verifies a detached ``signature`` over ``data`` using ``public_key_pem``, per
    ``algorithm``. Raises if ``public_key_pem`` is not parseable, or does not match the declared
    algorithm's expected key type -- an actual signature mismatch returns ``False``, it does not
    raise."""
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    try:
        if algorithm == "ed25519":
            if not isinstance(public_key, Ed25519PublicKey):
                raise TypeError(
                    f"Pinned key is not an Ed25519 public key (got {type(public_key).__name__})"
                )
            public_key.verify(signature, data)
        else:
            if not isinstance(public_key, RSAPublicKey):
                raise TypeError(
                    f"Pinned key is not an RSA public key (got {type(public_key).__name__})"
                )
            public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def _default_fetch(url: str, timeout_seconds: float) -> bytes:
    """Default ``FetchImpl``: a plain synchronous GET via ``urllib.request``, with a hard
    timeout so a hung/unresponsive manifest host cannot stall a connection attempt
    indefinitely -- the same rationale ``network_egress.py``'s DNS-lookup timeout already
    applies. Raises (``urllib.error.URLError``/``HTTPError``, ``TimeoutError``, or any other
    exception) rather than returning a value implying success on failure."""
    request = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
        status = getattr(response, "status", None) or response.getcode()
        if status is None or status < 200 or status >= 300:
            raise RuntimeError(f"Manifest fetch returned HTTP {status}")
        return response.read()


def _fetch_manifest_envelope(
    url: str, fetch_impl: FetchImpl, timeout_seconds: float
) -> McpManifestEnvelope:
    raw = fetch_impl(url, timeout_seconds)
    try:
        body = json.loads(raw)
    except (json.JSONDecodeError, TypeError, UnicodeDecodeError) as error:
        raise ValueError(f"Manifest response is not valid JSON: {error}") from error

    manifest = body.get("manifest") if isinstance(body, dict) else None
    signature = body.get("signature") if isinstance(body, dict) else None
    key_id = body.get("keyId") if isinstance(body, dict) else None
    if not isinstance(manifest, str) or not isinstance(signature, str) or not isinstance(key_id, str):
        raise ValueError(
            "Manifest response is missing one or more required fields "
            "(manifest, signature, keyId) or a field is not a string."
        )
    return McpManifestEnvelope(manifest_bytes=manifest, signature_b64=signature, key_id=key_id)


def verify_mcp_server_manifest(
    manifest_url_or_envelope: Union[str, McpManifestEnvelope],
    pinned_keys: Sequence[PinnedPublicKey],
    fetch_impl: Optional[FetchImpl] = None,
    timeout_seconds: float = DEFAULT_MANIFEST_FETCH_TIMEOUT_SECONDS,
) -> McpTrustVerdict:
    """Verifies an MCP server manifest's detached signature against a pinned public-key list
    before any tool the manifest declares may be trusted. Accepts either a manifest URL (fetched
    via ``fetch_impl`` or the default ``urllib``-based fetch, subject to ``timeout_seconds``) or
    an already-fetched ``McpManifestEnvelope`` directly.

    Fail-closed on every path, never a silent allow:

    - No pinned keys configured -> ``deny``.
    - Manifest URL unreachable, times out, or returns a malformed/non-2xx response -> ``deny``.
    - Envelope's ``key_id`` does not match any pinned key -> ``deny``.
    - Signature or manifest bytes are malformed (undecodable base64, etc.) -> ``deny``.
    - Signature verification raises (a malformed or mismatched-type pinned public key) -> ``deny``.
    - Signature does not verify against the matched pinned key -> ``deny``. This includes a
      bit-flipped/tampered manifest with its original (now-mismatched) signature left in place --
      see ``test_mcp_trust.py``'s tampered-manifest test for a direct proof, not just an
      assertion.
    - Only a signature that positively verifies against a pinned key returns ``allow``.
    """
    if not pinned_keys:
        return McpTrustVerdict(
            "deny",
            "No pinned public keys configured -- refusing to trust any manifest signature "
            "(fail closed).",
        )

    if isinstance(manifest_url_or_envelope, str):
        fetch = fetch_impl or _default_fetch
        try:
            envelope = _fetch_manifest_envelope(
                manifest_url_or_envelope, fetch, timeout_seconds
            )
        except Exception as error:  # noqa: BLE001 -- any fetch/parse failure fails closed
            return McpTrustVerdict(
                "deny",
                f'Manifest unreachable at "{manifest_url_or_envelope}": {error}. '
                "Failing closed.",
            )
    else:
        envelope = manifest_url_or_envelope

    key = next((k for k in pinned_keys if k.key_id == envelope.key_id), None)
    if key is None:
        return McpTrustVerdict(
            "deny",
            f'Manifest signed with keyId "{envelope.key_id}", which is not in the pinned '
            "key list. Failing closed.",
        )

    try:
        signature_bytes = base64.b64decode(envelope.signature_b64, validate=True)
        if not signature_bytes:
            raise ValueError("decoded signature is empty")
        data_bytes = envelope.manifest_bytes.encode("utf-8")
    except Exception as error:  # noqa: BLE001 -- any decoding failure fails closed
        return McpTrustVerdict(
            "deny", f"Malformed manifest signature encoding: {error}. Failing closed."
        )

    try:
        verified = _verify_signature_bytes(
            key.algorithm, key.public_key_pem, data_bytes, signature_bytes
        )
    except Exception as error:  # noqa: BLE001 -- any verification failure fails closed
        return McpTrustVerdict(
            "deny",
            f'Signature verification against pinned key "{key.key_id}" raised ({error}) -- '
            "treating as unverified. Failing closed.",
        )

    if not verified:
        return McpTrustVerdict(
            "deny",
            f'Manifest signature does not verify against pinned key "{key.key_id}". '
            "Failing closed.",
        )

    return McpTrustVerdict(
        "allow",
        f'Manifest signature verified against pinned key "{key.key_id}" ({key.algorithm}).',
    )


def assert_mcp_server_trusted(
    request: McpServerConnectionRequest, policy: McpTrustPolicy
) -> McpTrustVerdict:
    """The single connection-time gate combining both primitives: an MCP server's tools are
    trusted only if its origin is on the allowlist AND its manifest's signature verifies against
    a pinned key. Either check failing alone is a hard deny -- there is no partial-trust state,
    and origin is checked first so a manifest fetch (network I/O) is never attempted for an
    origin that was never going to be trusted anyway.
    """
    if not is_origin_allowed(request.origin, policy.allowed_origins):
        return McpTrustVerdict(
            "deny",
            f'Origin "{request.origin}" is not on the connection-time allowlist. '
            "Failing closed.",
        )
    return verify_mcp_server_manifest(
        request.manifest,
        policy.pinned_keys,
        fetch_impl=policy.fetch_impl,
        timeout_seconds=policy.timeout_seconds,
    )


__all__ = [
    "McpTrustDecision",
    "Algorithm",
    "FetchImpl",
    "DEFAULT_MANIFEST_FETCH_TIMEOUT_SECONDS",
    "PinnedPublicKey",
    "McpManifestEnvelope",
    "McpTrustVerdict",
    "McpServerConnectionRequest",
    "McpTrustPolicy",
    "is_origin_allowed",
    "verify_mcp_server_manifest",
    "assert_mcp_server_trusted",
]
