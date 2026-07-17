"""TG04 -- Credential/Secret Access.

Ported from ``packages/toolgovern/src/classifier/credential-access.ts``.

Fires when a call reads ``.env``, ``.ssh``, ``.aws/credentials``, OS keychain entries, or dumps
the bulk process environment, and that resource is not present in the caller's declared
credential scope.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from ..types import RuleContext, RuleMatch
from .util import (
    extract_command,
    extract_credential_name,
    extract_path,
    is_credential_granted,
    normalize_for_match,
    stringify_args,
)

_CATEGORY = "TG04"


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


def _path_or_command_text(ctx: RuleContext) -> Tuple[Optional[str], str]:
    """``text`` is normalized before pattern matching, so the same quote-splitting / $IFS /
    invisible-Unicode tricks that could dodge TG01's shell patterns cannot dodge these
    credential-path patterns either. ``path``, when present, is left as-is: it feeds a
    declared-scope allowlist membership check, not a regex match."""
    path = extract_path(ctx.args)
    text = normalize_for_match(path or extract_command(ctx.args) or stringify_args(ctx.args)).lower()
    return path, text


_DOTENV_PATTERN = re.compile(r"(^|[/\s])\.env(\.\w+)?\b")


def _dotenv_access_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    path, text = _path_or_command_text(ctx)
    found = _DOTENV_PATTERN.search(text)
    if not found:
        return None
    identifier = path or found.group(0).strip()
    if is_credential_granted(identifier, ctx.scope.credentials):
        return None
    return _match(
        "TG04-dotenv-access",
        "deny",
        f'Access to ".env" file "{identifier}" not in declared credential scope.',
        identifier,
    )


_SSH_KEY_PATTERN = re.compile(r"\.ssh/(id_\w+|config|authorized_keys)?")


def _ssh_key_access_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    path, text = _path_or_command_text(ctx)
    found = _SSH_KEY_PATTERN.search(text)
    if not found:
        return None
    identifier = path or found.group(0)
    if is_credential_granted(identifier, ctx.scope.credentials):
        return None
    return _match(
        "TG04-ssh-key-access",
        "deny",
        f'Access to SSH credential material "{identifier}" not in declared credential scope.',
        identifier,
    )


_CLOUD_CREDENTIAL_PATTERN = re.compile(r"\.(aws/(credentials|config)|gcp/[\w.-]+|azure/[\w.-]+|kube/config)")


def _cloud_credential_file_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    path, text = _path_or_command_text(ctx)
    found = _CLOUD_CREDENTIAL_PATTERN.search(text)
    if not found:
        return None
    identifier = path or found.group(0)
    if is_credential_granted(identifier, ctx.scope.credentials):
        return None
    return _match(
        "TG04-cloud-credential-file",
        "deny",
        f'Access to cloud credential file "{identifier}" not in declared credential scope.',
        identifier,
    )


_KEYCHAIN_PATTERN = re.compile(r"(security\s+find-generic-password|secret-tool\s+lookup|keytar)")


def _keychain_access_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    text = normalize_for_match(extract_command(ctx.args) or stringify_args(ctx.args)).lower()
    found = _KEYCHAIN_PATTERN.search(text)
    if not found:
        return None
    return _match(
        "TG04-keychain-access", "deny", "Access to OS keychain/secret-store credential material.", found.group(0)
    )


_BULK_ENV_DUMP_PATTERN = re.compile(r"^(env|printenv|export\s+-p)\s*$")


def _bulk_env_dump_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    text = normalize_for_match(extract_command(ctx.args) or "").lower().strip()
    found = _BULK_ENV_DUMP_PATTERN.search(text)
    if not found:
        return None
    return _match(
        "TG04-bulk-env-dump", "require-approval", "Bulk, unfiltered process-environment dump.", found.group(0)
    )


def _credential_name_not_in_scope_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    name = extract_credential_name(ctx.args)
    if not name:
        return None
    if is_credential_granted(name, ctx.scope.credentials):
        return None
    return _match(
        "TG04-credential-name-not-in-scope",
        "deny",
        f'Credential "{name}" is not in the declared credential scope.',
        name,
    )


credential_access_rules: List[_Rule] = [
    _Rule("TG04-dotenv-access", _CATEGORY, "Access to a .env-style file outside the declared credential scope.", _dotenv_access_evaluate),
    _Rule("TG04-ssh-key-access", _CATEGORY, "Access to a private SSH key or the .ssh directory.", _ssh_key_access_evaluate),
    _Rule("TG04-cloud-credential-file", _CATEGORY, "Access to a cloud provider credential/config file.", _cloud_credential_file_evaluate),
    _Rule("TG04-keychain-access", _CATEGORY, "Access to an OS-level keychain/secret store.", _keychain_access_evaluate),
    _Rule("TG04-bulk-env-dump", _CATEGORY, "Unfiltered dump of the full process environment.", _bulk_env_dump_evaluate),
    _Rule("TG04-credential-name-not-in-scope", _CATEGORY, "An explicitly named credential/secret argument is not in the declared scope.", _credential_name_not_in_scope_evaluate),
]
