"""Connection-time MCP-server trust gate for Agent Framework's HTTP-based MCP tools.

Addresses https://github.com/microsoft/agent-framework/issues/5864 ("Supply-chain: MCP server
allowlist & signature-verification primitive"), open at the time of writing and labeled both
``python`` and ``.NET`` -- Agent Framework itself has no built-in origin-allowlist or
manifest-signature-verification primitive at the ``MCPStreamableHTTPTool`` construction boundary;
any URL is connected to, and its declared tools trusted, with no framework-level check.

toolgovern's ``mcp_trust`` module already implements exactly the primitive #5864 requests: an
explicit origin allowlist plus pinned-public-key manifest-signature verification, both fail-closed. This module is a thin, real wiring point demonstrating that a
toolgovern user does not need to wait for that framework feature to land upstream -- call
``assert_trusted_mcp_streamable_http_source()`` with the URL you are about to hand to
``agent_framework.MCPStreamableHTTPTool(...)``, before constructing it.

What this deliberately does NOT do: it does not monkey-patch or subclass
``MCPStreamableHTTPTool`` to run this check automatically on every connection -- the caller must
call it explicitly before constructing the tool, exactly like any other connection-time
precondition check. It also only covers Agent Framework's streamable-HTTP MCP transport (the one
with a network-reachable ``origin`` for #5864's threat model to apply to); the stdio transport
(``MCPStdioTool``) launches a local subprocess and has a different, non-network trust boundary
that toolgovern's ``mcp_trust`` module (an origin-allowlist-plus-manifest-signature primitive) does
not model.
"""

from __future__ import annotations

from toolgovern import (
    McpServerConnectionRequest,
    McpTrustPolicy,
    McpTrustVerdict,
    assert_mcp_server_trusted,
)

__all__ = ["McpServerNotTrustedError", "assert_trusted_mcp_streamable_http_source"]


class McpServerNotTrustedError(Exception):
    """Raised when an MCP server's origin or manifest signature fails toolgovern's connection-time
    trust check. Never raised alongside an ``allow`` verdict -- see
    ``assert_trusted_mcp_streamable_http_source()``."""

    def __init__(self, url: str, verdict: McpTrustVerdict) -> None:
        self.url = url
        self.verdict = verdict
        super().__init__(f"toolgovern: refusing to trust MCP server at {url!r}: {verdict.reason}")


def assert_trusted_mcp_streamable_http_source(url: str, policy: McpTrustPolicy) -> McpTrustVerdict:
    """Runs toolgovern's connection-time MCP trust gate against ``url`` and raises
    ``McpServerNotTrustedError`` if it is denied.

    Call this BEFORE constructing ``agent_framework.MCPStreamableHTTPTool(name=..., url=url,
    ...)`` -- it does not wrap or construct the tool itself, so it composes with every
    ``MCPStreamableHTTPTool`` constructor argument (``approval_mode``, ``allowed_tools``,
    ``sampling_approval_callback``, ...) unchanged.

    Args:
        url: The MCP server URL you are about to pass as ``MCPStreamableHTTPTool(url=...)``.
            Used as both the trust check's ``origin`` and its manifest URL -- callers whose
            manifest lives at a different, explicitly-trusted location should call
            ``toolgovern.assert_mcp_server_trusted()`` directly instead with a distinct
            ``McpServerConnectionRequest.manifest``.
        policy: The origin allowlist + pinned-key ``McpTrustPolicy`` to check against.

    Returns:
        The ``allow`` verdict, for logging/audit purposes -- callers that don't need it can
        ignore the return value; a ``deny`` verdict always raises rather than returning.

    Raises:
        McpServerNotTrustedError: The origin is not allowlisted, or the manifest signature does
            not verify against a pinned key. Fail-closed in every case -- see
            ``toolgovern.mcp_trust``'s own module docstring for the full list of deny conditions.
    """
    verdict = assert_mcp_server_trusted(
        McpServerConnectionRequest(origin=url, manifest=url),
        policy,
    )
    if verdict.decision != "allow":
        raise McpServerNotTrustedError(url, verdict)
    return verdict
