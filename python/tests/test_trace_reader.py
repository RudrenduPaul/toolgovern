"""Tests for trace_reader.py -- read_trace, filter_trace, verify_chain. Ported in spirit from
packages/toolgovern/test/trace/trace-reader.test.ts.

This is the dedicated crypto-correctness suite for the audit trail signing mechanism: it proves
(not just asserts in prose) that the unkeyed sha256 scheme is forgeable by anyone with write
access to the trace file, and that the optional hmac-sha256 keyed scheme closes that gap.
"""

import dataclasses
import json
from datetime import datetime, timedelta, timezone

import pytest

from toolgovern import (
    ScopeDeclaration,
    TraceEntryInput,
    TraceWriter,
    TraceWriterOptions,
    VerifyChainOptions,
    filter_trace,
    parse_since,
    read_trace,
    verify_chain,
)
from toolgovern.trace.trace_writer import compute_entry_signature


def _input(session_id="s1", agent_id="a1", decision="allow", rule_fired=None, tool="shell"):
    return TraceEntryInput(
        session_id=session_id,
        agent_id=agent_id,
        tool=tool,
        args={"command": "ls"},
        decision=decision,
        rule_fired=rule_fired or [],
        declared_scope=ScopeDeclaration(),
    )


class TestReadTrace:
    def test_reads_written_entries(self, tmp_path):
        path = str(tmp_path / "trace.jsonl")
        writer = TraceWriter(path)
        writer.append(_input())
        writer.append(_input())
        entries = read_trace(path)
        assert len(entries) == 2

    def test_skips_blank_lines(self, tmp_path):
        path = tmp_path / "trace.jsonl"
        writer = TraceWriter(str(path))
        writer.append(_input())
        with open(path, "a", encoding="utf-8") as f:
            f.write("\n\n")
        entries = read_trace(str(path))
        assert len(entries) == 1

    def test_malformed_line_raises(self, tmp_path):
        path = tmp_path / "trace.jsonl"
        path.write_text("not valid json\n", encoding="utf-8")
        with pytest.raises(ValueError):
            read_trace(str(path))


class TestVerifyChainUnkeyed:
    def test_valid_chain_verifies(self, tmp_path):
        path = str(tmp_path / "trace.jsonl")
        writer = TraceWriter(path)
        writer.append(_input())
        writer.append(_input())
        entries = read_trace(path)
        result = verify_chain(entries)
        assert result.valid
        assert len(result.issues) == 0

    def test_detects_tampered_field_with_stale_signature(self, tmp_path):
        path = str(tmp_path / "trace.jsonl")
        writer = TraceWriter(path)
        writer.append(_input())
        entries = read_trace(path)
        tampered = dataclasses.replace(entries[0], tool="TAMPERED-TOOL")
        result = verify_chain([tampered])
        assert not result.valid
        assert any("Signature does not match" in i.reason for i in result.issues)

    def test_documents_residual_limitation_of_unkeyed_scheme(self, tmp_path):
        """The unkeyed sha256: scheme proves an entry has not changed since it was written, but
        it does NOT stop an attacker with write access to the trace file from editing an entry
        and recomputing a valid signature -- the hash requires no secret to reproduce. This test
        proves that limitation directly rather than only asserting it in prose."""
        path = str(tmp_path / "trace.jsonl")
        writer = TraceWriter(path)
        writer.append(_input())
        entries = read_trace(path)

        # Attacker edits the entry AND recomputes a valid signature -- no secret required.
        tampered = dataclasses.replace(entries[0], tool="ATTACKER-CONTROLLED-TOOL", signature="")
        forged_signature = compute_entry_signature(tampered)
        forged = dataclasses.replace(tampered, signature=forged_signature)

        result = verify_chain([forged])
        # The forged entry passes signature verification -- this is the documented, disclosed
        # limitation of the default unkeyed scheme, not a bug.
        signature_issues = [i for i in result.issues if "Signature does not match" in i.reason]
        assert signature_issues == []

    def test_broken_prior_trace_id_link_detected(self, tmp_path):
        path = str(tmp_path / "trace.jsonl")
        writer = TraceWriter(path)
        writer.append(_input())
        writer.append(_input())
        entries = read_trace(path)
        broken = dataclasses.replace(entries[1], prior_trace_id="some-other-id")
        result = verify_chain([entries[0], broken])
        assert not result.valid
        assert any("prior_trace_id" in i.reason for i in result.issues)

    def test_unrecognized_scheme_reported(self, tmp_path):
        path = str(tmp_path / "trace.jsonl")
        writer = TraceWriter(path)
        writer.append(_input())
        entries = read_trace(path)
        bad = dataclasses.replace(entries[0], signature="md5:deadbeef")
        result = verify_chain([bad])
        assert not result.valid
        assert any("Unrecognized signature scheme" in i.reason for i in result.issues)


class TestVerifyChainHmacKeyed:
    def test_round_trip_verifies_with_correct_key(self, tmp_path):
        path = str(tmp_path / "trace.jsonl")
        key = b"correct-horse-battery-staple"
        writer = TraceWriter(path, TraceWriterOptions(secret_key=key))
        writer.append(_input())
        entries = read_trace(path)
        result = verify_chain(entries, VerifyChainOptions(secret_key=key))
        assert result.valid

    def test_missing_key_is_reported_as_issue_not_silently_valid(self, tmp_path):
        path = str(tmp_path / "trace.jsonl")
        writer = TraceWriter(path, TraceWriterOptions(secret_key=b"secret"))
        writer.append(_input())
        entries = read_trace(path)
        result = verify_chain(entries)  # no key supplied
        assert not result.valid
        assert any("no secret_key was supplied" in i.reason for i in result.issues)

    def test_wrong_key_is_rejected(self, tmp_path):
        path = str(tmp_path / "trace.jsonl")
        writer = TraceWriter(path, TraceWriterOptions(secret_key=b"real-key"))
        writer.append(_input())
        entries = read_trace(path)
        result = verify_chain(entries, VerifyChainOptions(secret_key=b"wrong-key"))
        assert not result.valid

    def test_unkeyed_entry_verifies_even_when_key_supplied(self, tmp_path):
        """A sha256: entry must always be recomputed unkeyed, even if the caller supplies a
        secret_key -- otherwise every legitimate unkeyed entry would spuriously fail chain
        verification against a key it was never signed with. This is a real regression the TS
        implementation hit during manual QA (see docs/security-model.md finding #4)."""
        path = str(tmp_path / "trace.jsonl")
        writer = TraceWriter(path)  # unkeyed
        writer.append(_input())
        entries = read_trace(path)
        result = verify_chain(entries, VerifyChainOptions(secret_key=b"some-key-that-was-never-used"))
        assert result.valid, result.issues

    def test_forged_entry_with_wrong_key_detected(self, tmp_path):
        path = str(tmp_path / "trace.jsonl")
        real_key = b"real-key"
        writer = TraceWriter(path, TraceWriterOptions(secret_key=real_key))
        writer.append(_input())
        entries = read_trace(path)
        tampered = dataclasses.replace(entries[0], tool="FORGED", signature="")
        forged_signature = compute_entry_signature(tampered, secret_key=b"attacker-guessed-key")
        forged = dataclasses.replace(tampered, signature=forged_signature)
        result = verify_chain([forged], VerifyChainOptions(secret_key=real_key))
        assert not result.valid


class TestParseSince:
    def test_minutes(self):
        now = datetime(2026, 7, 17, 12, 0, 0, tzinfo=timezone.utc)
        cutoff = parse_since("30m", now)
        assert cutoff == now - timedelta(minutes=30)

    def test_hours(self):
        now = datetime(2026, 7, 17, 12, 0, 0, tzinfo=timezone.utc)
        cutoff = parse_since("24h", now)
        assert cutoff == now - timedelta(hours=24)

    def test_days(self):
        now = datetime(2026, 7, 17, 12, 0, 0, tzinfo=timezone.utc)
        cutoff = parse_since("7d", now)
        assert cutoff == now - timedelta(days=7)

    def test_invalid_unit_raises(self):
        with pytest.raises(ValueError):
            parse_since("5s")

    def test_iso_timestamp(self):
        cutoff = parse_since("2026-01-01T00:00:00+00:00")
        assert cutoff.year == 2026


class TestFilterTrace:
    def test_filters_by_decision(self, tmp_path):
        path = str(tmp_path / "trace.jsonl")
        writer = TraceWriter(path)
        writer.append(_input(decision="allow"))
        writer.append(_input(decision="deny", rule_fired=["TG01-rm-rf"]))
        entries = read_trace(path)
        from toolgovern import TraceQuery

        filtered = filter_trace(entries, TraceQuery(decision="deny"))
        assert len(filtered) == 1
        assert filtered[0].decision == "deny"

    def test_filters_by_agent_id(self, tmp_path):
        path = str(tmp_path / "trace.jsonl")
        writer = TraceWriter(path)
        writer.append(_input(agent_id="agent-a"))
        writer.append(_input(agent_id="agent-b"))
        entries = read_trace(path)
        from toolgovern import TraceQuery

        filtered = filter_trace(entries, TraceQuery(agent_id="agent-b"))
        assert len(filtered) == 1
        assert filtered[0].agent_id == "agent-b"

    def test_filters_by_rule_id(self, tmp_path):
        path = str(tmp_path / "trace.jsonl")
        writer = TraceWriter(path)
        writer.append(_input(decision="deny", rule_fired=["TG01-rm-rf"]))
        writer.append(_input(decision="deny", rule_fired=["TG04-dotenv-access"]))
        entries = read_trace(path)
        from toolgovern import TraceQuery

        filtered = filter_trace(entries, TraceQuery(rule_id="TG04-dotenv-access"))
        assert len(filtered) == 1
