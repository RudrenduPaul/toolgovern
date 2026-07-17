"""Tests for TraceWriter -- entry construction, chaining, hashing. Ported in spirit from
packages/toolgovern/test/trace/trace-writer.test.ts.
"""

import json
import os

from toolgovern import ScopeDeclaration, TraceEntryInput, TraceWriter, TraceWriterOptions


def _input(session_id="s1", agent_id="a1", decision="allow", rule_fired=None):
    return TraceEntryInput(
        session_id=session_id,
        agent_id=agent_id,
        tool="shell",
        args={"command": "ls"},
        decision=decision,
        rule_fired=rule_fired or [],
        declared_scope=ScopeDeclaration(),
    )


def test_append_returns_signed_entry(tmp_path):
    writer = TraceWriter(str(tmp_path / "trace.jsonl"))
    entry = writer.append(_input())
    assert entry.signature.startswith("sha256:")
    assert entry.trace_id.startswith("tg_")
    assert entry.prior_trace_id is None


def test_second_entry_chains_to_first(tmp_path):
    writer = TraceWriter(str(tmp_path / "trace.jsonl"))
    e1 = writer.append(_input())
    e2 = writer.append(_input())
    assert e2.prior_trace_id == e1.trace_id


def test_different_sessions_chain_independently(tmp_path):
    writer = TraceWriter(str(tmp_path / "trace.jsonl"))
    e1 = writer.append(_input(session_id="s1"))
    e2 = writer.append(_input(session_id="s2"))
    assert e1.prior_trace_id is None
    assert e2.prior_trace_id is None


def test_creates_parent_directories(tmp_path):
    nested = tmp_path / "a" / "b" / "c" / "trace.jsonl"
    writer = TraceWriter(str(nested))
    writer.append(_input())
    assert os.path.exists(nested)


def test_writes_one_json_line_per_entry(tmp_path):
    path = tmp_path / "trace.jsonl"
    writer = TraceWriter(str(path))
    writer.append(_input())
    writer.append(_input())
    lines = path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2
    for line in lines:
        json.loads(line)  # must be valid JSON


def test_hmac_signed_entry_has_hmac_prefix(tmp_path):
    writer = TraceWriter(str(tmp_path / "trace.jsonl"), TraceWriterOptions(secret_key=b"secret"))
    entry = writer.append(_input())
    assert entry.signature.startswith("hmac-sha256:")


def test_different_keys_produce_different_signatures(tmp_path):
    w1 = TraceWriter(str(tmp_path / "t1.jsonl"), TraceWriterOptions(secret_key=b"key-a"))
    w2 = TraceWriter(str(tmp_path / "t2.jsonl"), TraceWriterOptions(secret_key=b"key-b"))
    e1 = w1.append(_input())
    e2 = w2.append(_input())
    assert e1.signature != e2.signature
