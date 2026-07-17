"""``IdempotencyCache`` -- the primitive behind ``govern_tool()``'s optional ``idempotency``
option.

Ported from ``packages/toolgovern/src/middleware/idempotency-cache.ts``.

SCOPE AND LIMITATIONS (read before relying on this for anything beyond a single-process first
pass):

- This is a plain in-process dict. It does NOT survive a process restart, and it is NOT shared
  across multiple processes or replicas (e.g. horizontally-scaled workers behind a load
  balancer, or a serverless function that spins up a fresh instance per invocation). Two
  replicas each hold their own independent cache, so a retry that happens to land on a
  different replica than the original call will NOT be deduplicated.
- This is intentionally scoped as a first pass for the common single-process case (a
  long-running agent runtime, a single server instance, a CLI run). Cross-process /
  distributed idempotency (e.g. backed by Redis, or a database row with a unique constraint)
  is future work and is explicitly out of scope for this cache.
- A new cache is created per ``govern_tool()`` call, so it is scoped to that one gated tool
  instance -- it is never shared globally across every gate in a process.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional

from ..trace.canonical_json import canonical_json

_DEFAULT_IDEMPOTENCY_TTL_MS = 60_000


@dataclass(frozen=True)
class IdempotencyOptions:
    """Options for ``govern_tool()``'s optional idempotency dedup. Omitting this option
    entirely (the default) leaves ``govern_tool()``'s behavior completely unchanged -- every
    call executes independently, exactly as before this option existed."""

    enabled: bool = False
    ttl_ms: int = _DEFAULT_IDEMPOTENCY_TTL_MS
    """How long a completed result stays eligible to be replayed for an identical retry, in
    milliseconds."""


class _CacheEntry:
    __slots__ = ("result", "error", "settled", "expires_at", "event")

    def __init__(self) -> None:
        self.result: Any = None
        self.error: Optional[BaseException] = None
        self.settled: bool = False
        # None while the entry is still pending -- a pending claim never expires out from
        # under a call that is still running. Set to a concrete timestamp once the entry
        # settles, so the TTL clock starts counting from completion rather than from when the
        # call was first issued.
        self.expires_at: Optional[float] = None
        self.event = threading.Event()


class IdempotencyCache:
    """A scoped, in-memory claim-if-absent cache keyed on a stable serialization of tool name +
    arguments. See the module docstring for what this does and does not cover."""

    def __init__(self, ttl_ms: int = _DEFAULT_IDEMPOTENCY_TTL_MS) -> None:
        self._entries: Dict[str, _CacheEntry] = {}
        self._ttl_ms = ttl_ms
        self._lock = threading.Lock()

    @staticmethod
    def key_for(tool: str, args: Mapping[str, Any]) -> str:
        """Stable key for one tool+args combination. ``canonical_json`` sorts object keys
        recursively, so ``{"a":1,"b":2}`` and ``{"b":2,"a":1}`` hash identically -- argument
        insertion order must never cause two logically-identical calls to miss each other."""
        return f"{tool}:{canonical_json(dict(args))}"

    def claim_if_absent(self, key: str, run: Callable[[], Any]) -> Any:
        """Returns the cached result for ``key`` if a live (non-expired) entry exists,
        executing ``run`` only when there is no live claim. A failed execution is evicted
        immediately -- it is never cached as if it had succeeded, so a transient failure
        remains retryable. Only a completed result is eligible to be replayed for a retry
        within the TTL window."""
        now = time.monotonic() * 1000
        with self._lock:
            existing = self._entries.get(key)
            if existing and (existing.expires_at is None or existing.expires_at > now):
                claimed = existing
                is_new_claim = False
            else:
                if existing:
                    # Expired -- prune it so it doesn't linger.
                    del self._entries[key]
                claimed = _CacheEntry()
                self._entries[key] = claimed
                is_new_claim = True

        if not is_new_claim:
            claimed.event.wait()
            if claimed.error is not None:
                raise claimed.error
            return claimed.result

        try:
            result = run()
            claimed.result = result
            claimed.settled = True
            with self._lock:
                claimed.expires_at = time.monotonic() * 1000 + self._ttl_ms
            claimed.event.set()
            return result
        except BaseException as error:  # noqa: BLE001 -- re-raised immediately below
            claimed.error = error
            claimed.settled = True
            with self._lock:
                self._entries.pop(key, None)
            claimed.event.set()
            raise
