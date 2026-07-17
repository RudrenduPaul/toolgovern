"""Signed, append-only JSON Lines trace writer.

Ported from ``packages/toolgovern/src/trace/trace-writer.ts``.

Every gate decision -- allow, deny, or require-approval -- gets one line. ``prior_trace_id``
chains each entry to the one before it in the same session, so a reader can walk the chain and
detect a missing, reordered, or tampered entry.

By default, "signed" means a ``sha256:`` content hash, not a keyed signature -- a deliberate
v0.1 default that needs no key management: it proves an entry has not changed since it was
written, but it does not stop someone with write access to the trace file from editing an entry
and recomputing a signature that still passes, since the hash itself requires no secret to
reproduce. Pass ``secret_key`` in ``TraceWriter`` to sign with ``hmac-sha256:`` instead, which
closes that gap for anyone who does not also hold the key. See ``docs/security-model.md``.

toolgovern does not generate, store, or rotate the key -- the caller is responsible for its
lifecycle (e.g. a locally generated file with restrictive permissions, or a secret manager).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Sequence, Union

from ..types import AgentIdSource, Decision, ScopeDeclaration, TraceEntry, TraceEntryInput
from .canonical_json import canonical_json

# A raw bytes-like secret key, matching Node's BinaryLike (str/bytes) for this port's purposes.
SecretKeyLike = Union[bytes, str]


def _sha256_hex(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _hmac_sha256_hex(key: SecretKeyLike, content: str) -> str:
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    return hmac.new(key_bytes, content.encode("utf-8"), hashlib.sha256).hexdigest()


def _scope_to_content(scope: ScopeDeclaration) -> Dict[str, Any]:
    return {
        "network": scope.network if isinstance(scope.network, bool) else list(scope.network),
        "filesystem": list(scope.filesystem),
        "credentials": list(scope.credentials),
    }


def _entry_content(
    *,
    trace_id: Optional[str],
    timestamp: str,
    session_id: str,
    agent_id: str,
    tool: str,
    arguments_hash: str,
    decision: Decision,
    rule_fired: Sequence[str],
    declared_scope: ScopeDeclaration,
    agent_id_source: Optional[AgentIdSource],
    prior_trace_id: Optional[str],
    approved_by: Optional[str],
) -> str:
    """Builds the canonical-JSON content that gets hashed/signed. When ``trace_id`` is
    ``None``, the key is omitted entirely from the object (matching the TS ``withoutIds``
    object, which has no ``trace_id`` field at all before one has been derived) rather than
    included with an empty-string placeholder -- an empty string is still a value that would
    change the hash output versus a genuinely absent key.
    """
    content: Dict[str, Any] = {}
    if trace_id is not None:
        content["trace_id"] = trace_id
    content.update(
        {
            "timestamp": timestamp,
            "session_id": session_id,
            "agent_id": agent_id,
            "tool": tool,
            "arguments_hash": arguments_hash,
            "decision": decision,
            "rule_fired": list(rule_fired),
            "declared_scope": _scope_to_content(declared_scope),
            "agent_id_source": agent_id_source,
            "prior_trace_id": prior_trace_id,
            "approved_by": approved_by,
        }
    )
    return canonical_json(content)


def compute_entry_content_hash(entry: TraceEntry) -> str:
    """Computes the content hash a TraceEntry should have, given everything except
    ``signature``. This is the unkeyed form -- kept for backward compatibility and as the
    fallback ``sha256:`` scheme ``compute_entry_signature()`` uses when no secret key is
    configured."""
    return _sha256_hex(
        _entry_content(
            trace_id=entry.trace_id,
            timestamp=entry.timestamp,
            session_id=entry.session_id,
            agent_id=entry.agent_id,
            tool=entry.tool,
            arguments_hash=entry.arguments_hash,
            decision=entry.decision,
            rule_fired=entry.rule_fired,
            declared_scope=entry.declared_scope,
            agent_id_source=entry.agent_id_source,
            prior_trace_id=entry.prior_trace_id,
            approved_by=entry.approved_by,
        )
    )


def compute_entry_signature(entry: TraceEntry, secret_key: Optional[SecretKeyLike] = None) -> str:
    """Computes what ``signature`` should be for ``entry`` (everything except ``signature``).

    With no ``secret_key``, this is ``sha256:<hex>`` of the entry's canonicalized content --
    proves the entry has not changed since it was written, but the hash is reproducible by
    anyone (no secret required), so it does not stop an attacker who has write access to the
    trace file from editing an entry and recomputing a signature that still verifies.

    With a ``secret_key``, this is ``hmac-sha256:<hex>`` -- only someone holding the same key
    can produce a signature that verifies. This is what makes the trace tamper-evident against
    an attacker who can write to the trace file but does not also hold the key. See
    ``docs/security-model.md`` for the residual limitation (an attacker who reads both the
    trace file and the key file can still forge a valid trace -- v0.1 has no external anchor or
    key-management service).
    """
    content = _entry_content(
        trace_id=entry.trace_id,
        timestamp=entry.timestamp,
        session_id=entry.session_id,
        agent_id=entry.agent_id,
        tool=entry.tool,
        arguments_hash=entry.arguments_hash,
        decision=entry.decision,
        rule_fired=entry.rule_fired,
        declared_scope=entry.declared_scope,
        agent_id_source=entry.agent_id_source,
        prior_trace_id=entry.prior_trace_id,
        approved_by=entry.approved_by,
    )
    if secret_key is not None:
        return f"hmac-sha256:{_hmac_sha256_hex(secret_key, content)}"
    return f"sha256:{_sha256_hex(content)}"


@dataclass(frozen=True)
class TraceWriterOptions:
    """Options for ``TraceWriter``.

    ``secret_key``: when provided, every entry is signed with ``hmac-sha256:<hex>`` using this
    key instead of the unkeyed ``sha256:<hex>`` content hash. toolgovern does not generate,
    store, or rotate this key -- the caller is responsible for its lifecycle. Pass the same key
    to ``verify_chain()``.
    """

    secret_key: Optional[SecretKeyLike] = None


class TraceWriter:
    """Appends signed, append-only JSON Lines trace entries to a file.

    Writes are serialized with a lock so concurrent calls within one process never interleave
    lines or race on the last-trace-id-per-session bookkeeping, which would silently break the
    chain (the Python port's equivalent of the TS implementation's promise write-queue).
    """

    def __init__(self, file_path: str, options: Optional[TraceWriterOptions] = None) -> None:
        self._file_path = file_path
        self._options = options or TraceWriterOptions()
        self._last_trace_id_by_session: Dict[str, Optional[str]] = {}
        self._lock = threading.Lock()

    def append(self, entry_input: TraceEntryInput) -> TraceEntry:
        """Appends one gate decision to the trace file and returns the entry that was written."""
        with self._lock:
            prior_trace_id = self._last_trace_id_by_session.get(entry_input.session_id)
            now = datetime.now(timezone.utc)
            timestamp = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
            arguments_hash = f"sha256:{_sha256_hex(canonical_json(dict(entry_input.args)))}"
            rule_fired = list(entry_input.rule_fired)

            # trace_id is derived from the entry's own (unkeyed) content hash of everything
            # else -- it is an identifier, not a security boundary, so it stays
            # reproducible/public even when the signature itself is keyed.
            id_seed_content = _entry_content(
                trace_id=None,
                timestamp=timestamp,
                session_id=entry_input.session_id,
                agent_id=entry_input.agent_id,
                tool=entry_input.tool,
                arguments_hash=arguments_hash,
                decision=entry_input.decision,
                rule_fired=rule_fired,
                declared_scope=entry_input.declared_scope,
                agent_id_source=entry_input.agent_id_source,
                prior_trace_id=prior_trace_id,
                approved_by=entry_input.approved_by,
            )
            id_seed_hash = _sha256_hex(id_seed_content)
            trace_id = f"tg_{timestamp[:10]}_{id_seed_hash[:6]}"

            unsigned_entry = TraceEntry(
                trace_id=trace_id,
                timestamp=timestamp,
                session_id=entry_input.session_id,
                agent_id=entry_input.agent_id,
                tool=entry_input.tool,
                arguments_hash=arguments_hash,
                decision=entry_input.decision,
                rule_fired=rule_fired,
                declared_scope=entry_input.declared_scope,
                agent_id_source=entry_input.agent_id_source,
                prior_trace_id=prior_trace_id,
                approved_by=entry_input.approved_by,
                signature="",
            )
            signature = compute_entry_signature(unsigned_entry, self._options.secret_key)
            entry = TraceEntry(
                trace_id=trace_id,
                timestamp=timestamp,
                session_id=entry_input.session_id,
                agent_id=entry_input.agent_id,
                tool=entry_input.tool,
                arguments_hash=arguments_hash,
                decision=entry_input.decision,
                rule_fired=rule_fired,
                declared_scope=entry_input.declared_scope,
                agent_id_source=entry_input.agent_id_source,
                prior_trace_id=prior_trace_id,
                approved_by=entry_input.approved_by,
                signature=signature,
            )

            os.makedirs(os.path.dirname(self._file_path) or ".", exist_ok=True)
            with open(self._file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")

            self._last_trace_id_by_session[entry_input.session_id] = trace_id
            return entry
