"""toolgovern-integration-claude-agent-sdk -- govern Claude Agent SDK tool calls with toolgovern.

See ``hook.py`` for ``governed_pretooluse_hook()``, the ``PreToolUse``-hook factory this package
exists to provide.
"""

from __future__ import annotations

from .hook import (
    AsyncApprovalHandler,
    GovernedHookOptions,
    InvalidHookInputError,
    governed_pretooluse_hook,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "AsyncApprovalHandler",
    "GovernedHookOptions",
    "InvalidHookInputError",
    "governed_pretooluse_hook",
]
