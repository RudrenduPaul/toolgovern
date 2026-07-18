"""toolgovern integration for Microsoft Agent Framework (Python).

Python-only. A .NET port of Agent Framework is explicitly out of scope for this package -- see
README.md, "Scope and limitations". This package covers three real, tested integration points
against the actual ``agent_framework`` PyPI package (``agent-framework-core`` /
``agent-framework``):

- ``governed_function_tool()`` (``tool.py``) -- wrap a plain callable in a real
  ``agent_framework.FunctionTool`` whose body is gated by toolgovern's ``govern_tool()``.
- ``ToolGovernFunctionMiddleware`` (``middleware.py``) -- a ``FunctionMiddleware`` that surfaces a
  per-call require-approval decision through Agent Framework's own
  ``function_approval_request``/``function_approval_response`` content types, backed by
  toolgovern's durable ``PendingApprovalRegistry``.
- ``assert_trusted_mcp_streamable_http_source()`` (``mcp_trust.py``) -- a connection-time
  origin-allowlist + manifest-signature gate for ``MCPStreamableHTTPTool``, using toolgovern's
  own ``mcp_trust`` module.
"""

from __future__ import annotations

from .mcp_trust import McpServerNotTrustedError, assert_trusted_mcp_streamable_http_source
from .middleware import ToolGovernFunctionMiddleware
from .tool import governed_function_tool

__all__ = [
    "governed_function_tool",
    "ToolGovernFunctionMiddleware",
    "McpServerNotTrustedError",
    "assert_trusted_mcp_streamable_http_source",
]
