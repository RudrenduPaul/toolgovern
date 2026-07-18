"""Tests for ``toolgovern.mcp_trust`` -- mirrors
``packages/toolgovern/test/mcp-trust/index.test.ts`` case for case, including the genuine
tampered-manifest signature-verification proof."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Callable

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from toolgovern import (
    McpManifestEnvelope,
    McpServerConnectionRequest,
    McpTrustPolicy,
    PinnedPublicKey,
    assert_mcp_server_trusted,
    is_origin_allowed,
    verify_mcp_server_manifest,
)


@dataclass
class _KeyFixture:
    pinned: PinnedPublicKey
    sign: Callable[[bytes], bytes]


def make_ed25519_key(key_id: str) -> _KeyFixture:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return _KeyFixture(
        pinned=PinnedPublicKey(key_id=key_id, algorithm="ed25519", public_key_pem=public_pem),
        sign=lambda data: private_key.sign(data),
    )


def make_rsa_key(key_id: str) -> _KeyFixture:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return _KeyFixture(
        pinned=PinnedPublicKey(key_id=key_id, algorithm="rsa-sha256", public_key_pem=public_pem),
        sign=lambda data: private_key.sign(data, padding.PKCS1v15(), hashes.SHA256()),
    )


def envelope_for(manifest_text: str, key: _KeyFixture) -> McpManifestEnvelope:
    signature = key.sign(manifest_text.encode("utf-8"))
    return McpManifestEnvelope(
        manifest_bytes=manifest_text,
        signature_b64=base64.b64encode(signature).decode("ascii"),
        key_id=key.pinned.key_id,
    )


# --------------------------------------------------------------------------------------------
# is_origin_allowed
# --------------------------------------------------------------------------------------------


def test_allows_exact_origin_match():
    assert is_origin_allowed("https://mcp.example.com", ["https://mcp.example.com"]) is True


def test_allows_bare_hostname_allowlist_entry_against_full_origin():
    assert is_origin_allowed("https://mcp.example.com", ["mcp.example.com"]) is True


def test_allows_full_origin_against_bare_hostname_regardless_of_scheme():
    assert is_origin_allowed("http://mcp.example.com", ["mcp.example.com"]) is True


def test_denies_origin_not_on_allowlist():
    assert is_origin_allowed("https://evil.io", ["https://mcp.example.com"]) is False


def test_does_not_implicitly_trust_subdomain_of_allowed_origin():
    # Deliberate divergence from TG03's host_matches_allowed(): a connection-time server
    # allowlist defaults to exact match, not subdomain trust.
    assert is_origin_allowed("https://evil.mcp.example.com", ["https://mcp.example.com"]) is False


def test_allows_subdomain_only_with_explicit_glob_entry():
    assert is_origin_allowed("https://team-a.mcp.example.com", ["*.mcp.example.com"]) is True
    assert is_origin_allowed("https://mcp.example.com", ["*.mcp.example.com"]) is True


def test_denies_unrelated_host_even_with_glob_entry_present():
    assert is_origin_allowed("https://evil.io", ["*.mcp.example.com"]) is False


def test_is_case_insensitive():
    assert is_origin_allowed("https://MCP.Example.COM", ["mcp.example.com"]) is True


def test_denies_when_allowlist_is_empty():
    assert is_origin_allowed("https://mcp.example.com", []) is False


def test_denies_empty_origin_string():
    assert is_origin_allowed("", ["https://mcp.example.com"]) is False


def test_ignores_blank_allowlist_entry():
    assert is_origin_allowed("https://mcp.example.com", ["   "]) is False


# --------------------------------------------------------------------------------------------
# verify_mcp_server_manifest -- inline envelope
# --------------------------------------------------------------------------------------------


def test_allows_manifest_with_verifying_ed25519_signature():
    key = make_ed25519_key("key-1")
    envelope = envelope_for('{"name":"acme-mcp","tools":["read_file"]}', key)

    result = verify_mcp_server_manifest(envelope, [key.pinned])

    assert result.decision == "allow"
    assert "key-1" in result.reason


def test_allows_manifest_with_verifying_rsa_sha256_signature():
    key = make_rsa_key("rsa-key-1")
    envelope = envelope_for('{"name":"acme-mcp","tools":["read_file"]}', key)

    result = verify_mcp_server_manifest(envelope, [key.pinned])

    assert result.decision == "allow"


def test_denies_bit_flipped_tampered_manifest_despite_original_signature():
    """The genuine tampered-manifest proof: sign the original bytes, flip exactly one character
    in the manifest text afterward (the signature field is left completely unchanged, exactly
    like an attacker editing a manifest in place without the private key), and confirm the
    untouched signature no longer verifies against the mutated bytes."""
    key = make_ed25519_key("key-1")
    original = '{"name":"acme-mcp","tools":["read_file"],"version":"1.0.0"}'
    envelope = envelope_for(original, key)

    tampered = original.replace('"1.0.0"', '"2.0.0"')
    assert tampered != original
    tampered_envelope = McpManifestEnvelope(
        manifest_bytes=tampered, signature_b64=envelope.signature_b64, key_id=envelope.key_id
    )

    result = verify_mcp_server_manifest(tampered_envelope, [key.pinned])

    assert result.decision == "deny"
    assert "does not verify" in result.reason


def test_denies_manifest_signed_by_key_not_in_pinned_list():
    signing_key = make_ed25519_key("untrusted-key")
    pinned_key = make_ed25519_key("trusted-key")
    envelope = envelope_for('{"name":"acme-mcp"}', signing_key)

    result = verify_mcp_server_manifest(envelope, [pinned_key.pinned])

    assert result.decision == "deny"
    assert "untrusted-key" in result.reason
    assert "not in the pinned" in result.reason


def test_denies_when_no_pinned_keys_configured():
    key = make_ed25519_key("key-1")
    envelope = envelope_for('{"name":"acme-mcp"}', key)

    result = verify_mcp_server_manifest(envelope, [])

    assert result.decision == "deny"
    assert "No pinned public keys configured" in result.reason


def test_denies_malformed_signature_rather_than_raising():
    key = make_ed25519_key("key-1")
    envelope = McpManifestEnvelope(
        manifest_bytes='{"name":"acme-mcp"}', signature_b64="", key_id=key.pinned.key_id
    )

    result = verify_mcp_server_manifest(envelope, [key.pinned])

    assert result.decision == "deny"


def test_denies_signature_verified_under_wrong_algorithm_label():
    # Sign with Ed25519, but pin the same public key material under the wrong declared
    # algorithm -- load_pem_public_key() parses fine, but the RSAPublicKey isinstance check
    # inside _verify_signature_bytes() rejects it, proving the algorithm tag is load-bearing.
    key = make_ed25519_key("key-1")
    envelope = envelope_for('{"name":"acme-mcp"}', key)
    mislabeled_key = PinnedPublicKey(
        key_id=key.pinned.key_id, algorithm="rsa-sha256", public_key_pem=key.pinned.public_key_pem
    )

    result = verify_mcp_server_manifest(envelope, [mislabeled_key])

    assert result.decision == "deny"


# --------------------------------------------------------------------------------------------
# verify_mcp_server_manifest -- fetched manifest URL
# --------------------------------------------------------------------------------------------


def test_fetches_manifest_url_and_allows_when_envelope_verifies():
    key = make_ed25519_key("key-1")
    envelope = envelope_for('{"name":"acme-mcp"}', key)
    calls = []

    def fetch_impl(url: str, timeout_seconds: float) -> bytes:
        calls.append(url)
        return json.dumps(
            {
                "manifest": envelope.manifest_bytes,
                "signature": envelope.signature_b64,
                "keyId": envelope.key_id,
            }
        ).encode("utf-8")

    result = verify_mcp_server_manifest(
        "https://mcp.example.com/manifest.json", [key.pinned], fetch_impl=fetch_impl
    )

    assert result.decision == "allow"
    assert calls == ["https://mcp.example.com/manifest.json"]


def test_fails_closed_when_manifest_url_unreachable():
    key = make_ed25519_key("key-1")

    def fetch_impl(url: str, timeout_seconds: float) -> bytes:
        raise ConnectionRefusedError("ECONNREFUSED")

    result = verify_mcp_server_manifest(
        "https://down.example.com/manifest.json", [key.pinned], fetch_impl=fetch_impl
    )

    assert result.decision == "deny"
    assert "unreachable" in result.reason


def test_fails_closed_on_non_2xx_response():
    key = make_ed25519_key("key-1")

    def fetch_impl(url: str, timeout_seconds: float) -> bytes:
        raise RuntimeError("Manifest fetch returned HTTP 404")

    result = verify_mcp_server_manifest(
        "https://mcp.example.com/manifest.json", [key.pinned], fetch_impl=fetch_impl
    )

    assert result.decision == "deny"
    assert "unreachable" in result.reason


def test_fails_closed_on_malformed_response_body():
    key = make_ed25519_key("key-1")

    def fetch_impl(url: str, timeout_seconds: float) -> bytes:
        return json.dumps({"manifest": "x"}).encode("utf-8")

    result = verify_mcp_server_manifest(
        "https://mcp.example.com/manifest.json", [key.pinned], fetch_impl=fetch_impl
    )

    assert result.decision == "deny"


def test_fails_closed_on_timeout():
    key = make_ed25519_key("key-1")

    def fetch_impl(url: str, timeout_seconds: float) -> bytes:
        raise TimeoutError(f"timed out after {timeout_seconds}s")

    result = verify_mcp_server_manifest(
        "https://slow.example.com/manifest.json", [key.pinned], fetch_impl=fetch_impl, timeout_seconds=0.02
    )

    assert result.decision == "deny"
    assert "unreachable" in result.reason


# --------------------------------------------------------------------------------------------
# assert_mcp_server_trusted
# --------------------------------------------------------------------------------------------


def test_denies_on_origin_alone_without_attempting_manifest_fetch():
    key = make_ed25519_key("key-1")
    calls = []

    def fetch_impl(url: str, timeout_seconds: float) -> bytes:
        calls.append(url)
        raise AssertionError("fetch_impl should never be called when origin is not allowed")

    result = assert_mcp_server_trusted(
        McpServerConnectionRequest(origin="https://evil.io", manifest="https://evil.io/manifest.json"),
        McpTrustPolicy(
            allowed_origins=["https://mcp.example.com"],
            pinned_keys=[key.pinned],
            fetch_impl=fetch_impl,
        ),
    )

    assert result.decision == "deny"
    assert "allowlist" in result.reason
    assert calls == []


def test_allows_only_when_origin_and_manifest_both_pass():
    key = make_ed25519_key("key-1")
    envelope = envelope_for('{"name":"acme-mcp"}', key)

    result = assert_mcp_server_trusted(
        McpServerConnectionRequest(origin="https://mcp.example.com", manifest=envelope),
        McpTrustPolicy(allowed_origins=["https://mcp.example.com"], pinned_keys=[key.pinned]),
    )

    assert result.decision == "allow"


def test_denies_when_origin_allowed_but_manifest_signature_invalid():
    signing_key = make_ed25519_key("untrusted")
    pinned_key = make_ed25519_key("trusted")
    envelope = envelope_for('{"name":"acme-mcp"}', signing_key)

    result = assert_mcp_server_trusted(
        McpServerConnectionRequest(origin="https://mcp.example.com", manifest=envelope),
        McpTrustPolicy(allowed_origins=["https://mcp.example.com"], pinned_keys=[pinned_key.pinned]),
    )

    assert result.decision == "deny"
