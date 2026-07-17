"""Helpers for validating and comparing ``ScopeDeclaration`` values.

Ported from ``packages/toolgovern/src/scoping/scope-declaration.ts``.

A ``ScopeDeclaration`` is intentionally simple: an agent gets access to what it declares, and
nothing else. There is no implicit "and everything under this is fine too" beyond the explicit
path-prefix / hostname-suffix / credential-identifier matching implemented here.
"""

from __future__ import annotations

from typing import Any, Optional

from ..types import ScopeDeclaration

# The empty scope: no network, no filesystem, no credentials. This is the default-deny floor.
EMPTY_SCOPE = ScopeDeclaration(network=False, filesystem=(), credentials=())


def is_valid_scope_declaration(value: Any) -> bool:
    if not isinstance(value, dict):
        return False

    network = value.get("network")
    network_ok = isinstance(network, bool) or (
        isinstance(network, list) and all(isinstance(h, str) for h in network)
    )
    filesystem = value.get("filesystem")
    filesystem_ok = isinstance(filesystem, list) and all(isinstance(p, str) for p in filesystem)
    credentials = value.get("credentials")
    credentials_ok = isinstance(credentials, list) and all(isinstance(c, str) for c in credentials)

    return network_ok and filesystem_ok and credentials_ok


def normalize_scope(partial: Optional[dict]) -> ScopeDeclaration:
    """Normalizes a partial/loosely-typed scope object into a fully-formed ScopeDeclaration,
    defaulting any missing field to the most restrictive value (default-deny)."""
    partial = partial or {}
    return ScopeDeclaration(
        network=partial.get("network", False),
        filesystem=tuple(partial.get("filesystem", ())),
        credentials=tuple(partial.get("credentials", ())),
    )


# Generous ceiling on agent_id length. Not a protocol limit -- just large enough that no
# realistic identity scheme (UUID, DNS name, URN, JWT sub claim) trips it, while still
# rejecting unbounded strings that look like a buffer-abuse or log-flooding attempt.
_MAX_AGENT_ID_LENGTH = 256


def _is_disallowed_control_code_point(code_point: int) -> bool:
    """Code points with no legitimate reason to appear in an agent identity string: ASCII
    control characters (0x00-0x1F, 0x7F) and the Unicode line/paragraph separators (0x2028,
    0x2029). Letting them through invites log-injection, null-byte truncation tricks, or
    terminal/ANSI escape abuse."""
    return (0x00 <= code_point <= 0x1F) or code_point == 0x7F or code_point in (0x2028, 0x2029)


def is_valid_agent_id(value: Any) -> bool:
    """Format-only validation for an agent_id string.

    IMPORTANT -- what this is NOT: this does not verify that a caller actually is the agent it
    claims to be. toolgovern has no cryptographic identity verification mechanism in v0.1; any
    caller can still supply any well-formed agent_id and have it accepted as-is (see
    docs/security-model.md). A string that passes is merely *well-formed* -- it remains just as
    much a bare, unverified claim as any other string that passes.

    What this DOES do: reject a narrow, concrete class of malformed/malicious inputs -- an
    empty string, a string past a sane length ceiling, or a string containing control
    characters/embedded null bytes that could be used for log injection or to confuse
    downstream string handling. This is a hygiene filter, not an authentication mechanism.
    """
    if not isinstance(value, str):
        return False
    if len(value) == 0:
        return False
    if len(value) > _MAX_AGENT_ID_LENGTH:
        return False
    for ch in value:
        if _is_disallowed_control_code_point(ord(ch)):
            return False
    return True
