"""Deterministic JSON serialization: object keys are sorted recursively so the same logical
content always hashes to the same bytes, regardless of the insertion order the caller used.

Ported from ``packages/toolgovern/src/trace/canonical-json.ts``. This is what makes the trace's
sha256 content hash reproducible and verifiable later.
"""

from __future__ import annotations

import json
from typing import Any


def _sort_keys_deep(value: Any) -> Any:
    if isinstance(value, list):
        return [_sort_keys_deep(v) for v in value]
    if isinstance(value, dict):
        return {key: _sort_keys_deep(value[key]) for key in sorted(value.keys())}
    return value


def canonical_json(value: Any) -> str:
    """Serializes ``value`` to JSON with all object keys sorted recursively (array order is
    preserved). ``separators`` matches JavaScript's ``JSON.stringify`` compact-by-default
    output (no extra whitespace), so the byte sequence signed by the TypeScript and Python
    implementations is identical for the same logical content."""
    return json.dumps(_sort_keys_deep(value), separators=(",", ":"), ensure_ascii=False)
