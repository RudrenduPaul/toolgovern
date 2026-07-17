"""Reads a JSON Lines trace file for local inspection, filtering, and chain verification.

Ported from ``packages/toolgovern/src/trace/trace-reader.ts``. Powers both
``toolgovern-cli audit`` and any programmatic post-session review.
"""

from __future__ import annotations

import hmac
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Sequence

from ..types import Decision, ScopeDeclaration, TraceEntry
from .trace_writer import SecretKeyLike, compute_entry_signature


def _signatures_match(actual: str, expected: str) -> bool:
    """Constant-time comparison of two signature strings. ``hmac.compare_digest`` requires
    equal-length inputs to stay constant-time; a length mismatch is checked first and
    short-circuits to False -- this leaks nothing an attacker doesn't already know, since both
    the scheme prefix and the hex-encoded hash length are fixed and public (``sha256:`` + 64
    hex chars, ``hmac-sha256:`` + 64 hex chars), not a function of the secret being compared."""
    actual_bytes = actual.encode("utf-8")
    expected_bytes = expected.encode("utf-8")
    if len(actual_bytes) != len(expected_bytes):
        return False
    return hmac.compare_digest(actual_bytes, expected_bytes)


@dataclass(frozen=True)
class TraceQuery:
    since: Optional[str] = None
    decision: Optional[Decision] = None
    agent_id: Optional[str] = None
    rule_id: Optional[str] = None
    """Matches entries where this rule ID appears anywhere in rule_fired."""


@dataclass(frozen=True)
class ChainVerificationIssue:
    trace_id: str
    reason: str


@dataclass(frozen=True)
class ChainVerificationResult:
    valid: bool
    issues: Sequence[ChainVerificationIssue] = field(default_factory=tuple)


@dataclass(frozen=True)
class VerifyChainOptions:
    """``secret_key`` is required to verify entries signed with ``hmac-sha256:``. Entries
    signed with the legacy unkeyed ``sha256:`` scheme verify without it."""

    secret_key: Optional[SecretKeyLike] = None


def _entry_from_dict(raw: dict) -> TraceEntry:
    scope_raw = raw.get("declared_scope", {})
    scope = ScopeDeclaration(
        network=scope_raw.get("network", False),
        filesystem=tuple(scope_raw.get("filesystem", ())),
        credentials=tuple(scope_raw.get("credentials", ())),
    )
    return TraceEntry(
        trace_id=raw["trace_id"],
        timestamp=raw["timestamp"],
        session_id=raw["session_id"],
        agent_id=raw["agent_id"],
        tool=raw["tool"],
        arguments_hash=raw["arguments_hash"],
        decision=raw["decision"],
        rule_fired=tuple(raw.get("rule_fired", ())),
        declared_scope=scope,
        signature=raw["signature"],
        prior_trace_id=raw.get("prior_trace_id"),
        agent_id_source=raw.get("agent_id_source"),
        approved_by=raw.get("approved_by"),
    )


def read_trace(file_path: str) -> List[TraceEntry]:
    """Reads and parses every line of a JSON Lines trace file. Blank lines are skipped."""
    with open(file_path, "r", encoding="utf-8") as f:
        raw = f.read()
    entries: List[TraceEntry] = []
    for index, line in enumerate(raw.split("\n")):
        trimmed = line.strip()
        if not trimmed:
            continue
        try:
            parsed = json.loads(trimmed)
        except json.JSONDecodeError as cause:
            raise ValueError(
                f"Malformed trace line {index + 1} in {file_path}: not valid JSON"
            ) from cause
        entries.append(_entry_from_dict(parsed))
    return entries


_SINCE_PATTERN = re.compile(r"^(\d+)(m|h|d)$")


def parse_since(since: str, now: Optional[datetime] = None) -> datetime:
    """Parses a ``since`` window string into an absolute cutoff datetime."""
    now = now or datetime.now(timezone.utc)
    match = _SINCE_PATTERN.match(since)
    if not match:
        try:
            as_date = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError as cause:
            raise ValueError(
                f'Invalid --since value "{since}". Use "<n>m", "<n>h", "<n>d", or an ISO 8601 timestamp.'
            ) from cause
        return as_date
    amount = int(match.group(1))
    unit = match.group(2)
    delta = {"m": timedelta(minutes=amount), "h": timedelta(hours=amount), "d": timedelta(days=amount)}[unit]
    return now - delta


def filter_trace(entries: Sequence[TraceEntry], query: TraceQuery) -> List[TraceEntry]:
    """Filters trace entries by time window, decision, agent identity, and/or fired rule ID."""
    cutoff = parse_since(query.since) if query.since else None
    result = []
    for entry in entries:
        if cutoff is not None:
            entry_time = datetime.fromisoformat(entry.timestamp.replace("Z", "+00:00"))
            if entry_time < cutoff:
                continue
        if query.decision and entry.decision != query.decision:
            continue
        if query.agent_id and entry.agent_id != query.agent_id:
            continue
        if query.rule_id and query.rule_id not in entry.rule_fired:
            continue
        result.append(entry)
    return result


def verify_chain(
    entries: Sequence[TraceEntry], options: Optional[VerifyChainOptions] = None
) -> ChainVerificationResult:
    """Recomputes each entry's signature and confirms it matches ``signature``, and confirms
    ``prior_trace_id`` correctly links to the previous entry in the same session. Returns every
    issue found rather than stopping at the first one, so a reviewer can see the full extent of
    a broken or tampered trace file.

    An entry signed ``hmac-sha256:`` cannot be verified without the matching ``secret_key`` --
    that is reported as an issue (not silently skipped, and not silently treated as valid),
    because a trace a reviewer cannot actually verify is not a trace they should trust as-is.
    """
    options = options or VerifyChainOptions()
    issues: List[ChainVerificationIssue] = []
    last_seen_by_session: Dict[str, Optional[str]] = {}

    for entry in entries:
        scheme = entry.signature.split(":", 1)[0]
        if scheme == "hmac-sha256" and options.secret_key is None:
            issues.append(
                ChainVerificationIssue(
                    trace_id=entry.trace_id,
                    reason="Entry is signed with hmac-sha256 but no secret_key was supplied to verify it.",
                )
            )
        elif scheme in ("hmac-sha256", "sha256"):
            # Only pass the key through for entries actually signed with it. A sha256: entry
            # must always be recomputed unkeyed, even if the caller supplied a secret_key
            # (e.g. verifying a trace file that turns out to predate keyed signing, or a
            # mixed-mode file) -- otherwise every legitimate unkeyed entry would spuriously
            # fail to verify against the wrong scheme.
            expected = compute_entry_signature(
                entry, options.secret_key if scheme == "hmac-sha256" else None
            )
            if not _signatures_match(entry.signature, expected):
                issues.append(
                    ChainVerificationIssue(
                        trace_id=entry.trace_id, reason="Signature does not match entry content."
                    )
                )
        else:
            issues.append(
                ChainVerificationIssue(
                    trace_id=entry.trace_id, reason=f'Unrecognized signature scheme "{scheme}".'
                )
            )

        expected_prior = last_seen_by_session.get(entry.session_id)
        if entry.prior_trace_id != expected_prior:
            issues.append(
                ChainVerificationIssue(
                    trace_id=entry.trace_id,
                    reason=(
                        f'prior_trace_id "{entry.prior_trace_id or "null"}" does not match the '
                        f'expected previous entry "{expected_prior or "null"}" for session '
                        f'"{entry.session_id}".'
                    ),
                )
            )
        last_seen_by_session[entry.session_id] = entry.trace_id

    return ChainVerificationResult(valid=len(issues) == 0, issues=issues)
