"""Real tests for assert_trusted_mcp_streamable_http_source() (issue #5864 wiring).

Uses toolgovern.McpTrustPolicy's own injectable fetch_impl to avoid a real network call while
still exercising the real signature-verification code path (a real Ed25519 keypair signs a real
manifest payload; verification runs for real against the pinned public key).
"""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from toolgovern import McpTrustPolicy, PinnedPublicKey

from toolgovern_integration_agent_framework import (
    McpServerNotTrustedError,
    assert_trusted_mcp_streamable_http_source,
)

_URL = "https://mcp.example.com/manifest"


def _signed_manifest_response(manifest_text: str, private_key, key_id: str) -> bytes:
    signature = private_key.sign(manifest_text.encode("utf-8"))
    body = {
        "manifest": manifest_text,
        "signature": base64.b64encode(signature).decode("ascii"),
        "keyId": key_id,
    }
    return json.dumps(body).encode("utf-8")


def _make_ed25519_pinned_key(key_id: str):
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return private_key, PinnedPublicKey(key_id=key_id, algorithm="ed25519", public_key_pem=public_pem)


def test_trusted_origin_and_verified_signature_returns_allow():
    private_key, pinned = _make_ed25519_pinned_key("prod-2026")
    manifest_text = '{"tools": ["search"]}'

    def fetch(url: str, timeout: float) -> bytes:
        assert url == _URL
        return _signed_manifest_response(manifest_text, private_key, "prod-2026")

    policy = McpTrustPolicy(
        allowed_origins=["mcp.example.com"],
        pinned_keys=[pinned],
        fetch_impl=fetch,
    )

    verdict = assert_trusted_mcp_streamable_http_source(_URL, policy)

    assert verdict.decision == "allow"


def test_origin_not_on_allowlist_raises_and_never_fetches_manifest():
    _, pinned = _make_ed25519_pinned_key("prod-2026")
    fetch_called = {"count": 0}

    def fetch(url: str, timeout: float) -> bytes:
        fetch_called["count"] += 1
        raise AssertionError("manifest must never be fetched for a disallowed origin")

    policy = McpTrustPolicy(
        allowed_origins=["other.example.com"],
        pinned_keys=[pinned],
        fetch_impl=fetch,
    )

    with pytest.raises(McpServerNotTrustedError) as excinfo:
        assert_trusted_mcp_streamable_http_source(_URL, policy)

    assert fetch_called["count"] == 0
    assert excinfo.value.url == _URL
    assert excinfo.value.verdict.decision == "deny"


def test_tampered_manifest_fails_signature_verification_and_raises():
    private_key, pinned = _make_ed25519_pinned_key("prod-2026")
    manifest_text = '{"tools": ["search"]}'
    tampered_text = '{"tools": ["search", "delete_everything"]}'

    def fetch(url: str, timeout: float) -> bytes:
        # Sign the ORIGINAL text but serve the TAMPERED text -- the signature must not verify.
        signature = private_key.sign(manifest_text.encode("utf-8"))
        body = {
            "manifest": tampered_text,
            "signature": base64.b64encode(signature).decode("ascii"),
            "keyId": "prod-2026",
        }
        return json.dumps(body).encode("utf-8")

    policy = McpTrustPolicy(
        allowed_origins=["mcp.example.com"],
        pinned_keys=[pinned],
        fetch_impl=fetch,
    )

    with pytest.raises(McpServerNotTrustedError):
        assert_trusted_mcp_streamable_http_source(_URL, policy)


def test_no_pinned_keys_fails_closed():
    policy = McpTrustPolicy(allowed_origins=["mcp.example.com"], pinned_keys=[])

    with pytest.raises(McpServerNotTrustedError):
        assert_trusted_mcp_streamable_http_source(_URL, policy)
