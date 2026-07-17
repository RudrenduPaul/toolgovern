"""Tests for canonical_json.py -- deterministic key-sorted serialization. Ported in spirit from
packages/toolgovern/test/trace/canonical-json.test.ts.
"""

from toolgovern.trace.canonical_json import canonical_json


def test_sorts_top_level_keys():
    assert canonical_json({"b": 2, "a": 1}) == canonical_json({"a": 1, "b": 2})


def test_sorts_nested_keys():
    a = {"outer": {"z": 1, "a": 2}}
    b = {"outer": {"a": 2, "z": 1}}
    assert canonical_json(a) == canonical_json(b)


def test_preserves_array_order():
    assert canonical_json([3, 1, 2]) != canonical_json([1, 2, 3])
    assert canonical_json({"list": [3, 1, 2]}) == canonical_json({"list": [3, 1, 2]})


def test_different_content_hashes_differently():
    assert canonical_json({"a": 1}) != canonical_json({"a": 2})


def test_none_and_booleans_serialize_stably():
    assert canonical_json({"a": None, "b": True, "c": False}) == canonical_json(
        {"c": False, "b": True, "a": None}
    )
