"""TG02 -- Filesystem Scope Escalation.

Ported from ``packages/toolgovern/src/classifier/filesystem-scope.ts``.

Fires when a call attempts a write, delete, or permission change outside the caller's declared
filesystem scope (``scope.filesystem``, a list of allowed path prefixes), or targets a small set
of sensitive absolute system directories regardless of scope.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence

from ..types import RuleContext, RuleMatch
from .util import (
    contains_path_traversal,
    extract_operation,
    extract_path,
    is_credential_granted,
    is_path_within,
    normalize_for_match,
)

_CATEGORY = "TG02"

_WRITE_OPS = {"write", "create", "append", "put", "save"}
_DELETE_OPS = {"delete", "remove", "unlink", "rm", "rmdir"}
_CHMOD_OPS = {"chmod", "chown", "setpermissions", "set_permissions"}
_READ_OPS = {"read", "get", "load", "fetch", "cat", "open"}
_SENSITIVE_SYSTEM_PREFIXES = ["/etc", "/usr", "/bin", "/sbin", "/system", "/private/etc"]


def _extract_normalized_path(args) -> Optional[str]:
    """Extracts a call's path argument and runs it through the same obfuscation-normalization
    pass TG01/TG03/TG04 already apply, so a path cannot dodge a scope or sensitive-prefix check
    by smuggling in a formatting character a literal/prefix comparison wouldn't see."""
    raw = extract_path(args)
    return normalize_for_match(raw) if raw else None


def _is_within_scope(path: str, filesystem: Sequence[str]) -> bool:
    if len(filesystem) == 0:
        return False
    return any(is_path_within(path, prefix) for prefix in filesystem)


@dataclass
class _Rule:
    id: str
    category: str
    description: str
    _evaluate: Callable[[RuleContext], Optional[RuleMatch]]

    def evaluate(self, ctx: RuleContext) -> Optional[RuleMatch]:
        return self._evaluate(ctx)


def _match(rule_id: str, decision: str, reason: str, matched_argument: str) -> RuleMatch:
    return RuleMatch(
        rule_id=rule_id,
        category=_CATEGORY,  # type: ignore[arg-type]
        decision=decision,  # type: ignore[arg-type]
        reason=reason,
        matched_argument=matched_argument,
    )


def _write_outside_scope_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    path = _extract_normalized_path(ctx.args)
    if not path:
        return None
    op = extract_operation(ctx.args) or ("write" if "write" in ctx.tool.lower() else "")
    if op not in _WRITE_OPS:
        return None
    if _is_within_scope(path, ctx.scope.filesystem):
        return None
    return _match(
        "TG02-write-outside-scope",
        "require-approval",
        f'Write target "{path}" is outside the declared filesystem scope.',
        path,
    )


def _delete_outside_scope_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    path = _extract_normalized_path(ctx.args)
    if not path:
        return None
    op = extract_operation(ctx.args) or ("delete" if "delete" in ctx.tool.lower() else "")
    if op not in _DELETE_OPS:
        return None
    if _is_within_scope(path, ctx.scope.filesystem):
        return None
    return _match(
        "TG02-delete-outside-scope",
        "deny",
        f'Delete target "{path}" is outside the declared filesystem scope.',
        path,
    )


def _chmod_outside_scope_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    path = _extract_normalized_path(ctx.args)
    if not path:
        return None
    op = extract_operation(ctx.args)
    if not op or op not in _CHMOD_OPS:
        return None
    if _is_within_scope(path, ctx.scope.filesystem):
        return None
    return _match(
        "TG02-chmod-outside-scope",
        "deny",
        f'Permission change on "{path}" is outside the declared filesystem scope.',
        path,
    )


def _read_outside_scope_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    path = _extract_normalized_path(ctx.args)
    if not path:
        return None
    op = extract_operation(ctx.args) or ("read" if "read" in ctx.tool.lower() else "")
    if op not in _READ_OPS:
        return None
    if _is_within_scope(path, ctx.scope.filesystem):
        return None
    if is_credential_granted(path, ctx.scope.credentials):
        return None
    return _match(
        "TG02-read-outside-scope",
        "require-approval",
        f'Read target "{path}" is outside the declared filesystem scope.',
        path,
    )


def _path_traversal_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    path = _extract_normalized_path(ctx.args)
    if not path:
        return None
    if not contains_path_traversal(path):
        return None
    return _match(
        "TG02-path-traversal", "deny", f'Path "{path}" contains traversal segments ("..").', path
    )


def _symlink_escape_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    op = extract_operation(ctx.args) or ""
    if "symlink" not in op and "link" not in op:
        return None
    path = _extract_normalized_path(ctx.args)
    if not path:
        return None
    if _is_within_scope(path, ctx.scope.filesystem):
        return None
    return _match(
        "TG02-symlink-escape",
        "deny",
        f'Symlink target "{path}" is outside the declared filesystem scope.',
        path,
    )


def _sensitive_system_path_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    path = _extract_normalized_path(ctx.args)
    if not path:
        return None
    op = extract_operation(ctx.args) or ""
    if op not in _WRITE_OPS and op not in _DELETE_OPS and op not in _CHMOD_OPS:
        return None
    # Case-insensitive, same as the original raw-prefix check this replaces -- every entry in
    # SENSITIVE_SYSTEM_PREFIXES is already lowercase.
    lower = path.lower()
    hit = next((p for p in _SENSITIVE_SYSTEM_PREFIXES if is_path_within(lower, p)), None)
    if not hit:
        return None
    return _match(
        "TG02-sensitive-system-path",
        "deny",
        f'Target "{path}" is under a sensitive system directory ({hit}).',
        path,
    )


filesystem_scope_rules: List[_Rule] = [
    _Rule("TG02-write-outside-scope", _CATEGORY, "A write/create targets a path outside the declared filesystem scope.", _write_outside_scope_evaluate),
    _Rule("TG02-delete-outside-scope", _CATEGORY, "A delete targets a path outside the declared filesystem scope.", _delete_outside_scope_evaluate),
    _Rule("TG02-chmod-outside-scope", _CATEGORY, "A permission change targets a path outside the declared filesystem scope.", _chmod_outside_scope_evaluate),
    _Rule(
        "TG02-read-outside-scope",
        _CATEGORY,
        "A read targets a path outside the caller's declared filesystem scope. An explicitly "
        "granted credential path (scope.credentials) is not flagged here.",
        _read_outside_scope_evaluate,
    ),
    _Rule("TG02-path-traversal", _CATEGORY, 'A path uses ".." segments that could escape a scoped prefix.', _path_traversal_evaluate),
    _Rule("TG02-symlink-escape", _CATEGORY, "A symlink/link operation targets a path outside the declared filesystem scope.", _symlink_escape_evaluate),
    _Rule("TG02-sensitive-system-path", _CATEGORY, "A write/delete targets a sensitive absolute system directory.", _sensitive_system_path_evaluate),
]
