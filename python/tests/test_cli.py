"""Tests for toolgovern-cli's validate and audit subcommands. Ported in spirit from
packages/toolgovern-cli/test/cli.test.ts.
"""

import json

from toolgovern import ScopeDeclaration, TraceEntryInput, TraceWriter, TraceWriterOptions
from toolgovern.cli import audit_command, parse_args, run_command, validate_command

VALID_POLICY_YAML = """
name: strict-shell
scope:
  network: false
  filesystem:
    - ./workspace
  credentials: []
"""


class TestParseArgs:
    def test_positional_and_flags(self):
        parsed = parse_args(["file.yml", "--json", "--since", "24h"])
        assert parsed.positional == ["file.yml"]
        assert parsed.flags == {"json": True, "since": "24h"}

    def test_boolean_flag_not_followed_by_value(self):
        parsed = parse_args(["--verify-chain", "--json"])
        assert parsed.flags == {"verify-chain": True, "json": True}


class TestValidateCommand:
    def test_valid_policy_exits_zero(self, tmp_path):
        path = tmp_path / "policy.yml"
        path.write_text(VALID_POLICY_YAML, encoding="utf-8")
        result = validate_command(str(path))
        assert result.code == 0
        assert "is a valid toolgovern policy" in result.stdout

    def test_missing_arg_exits_two(self):
        result = validate_command(None)
        assert result.code == 2

    def test_invalid_policy_exits_one(self, tmp_path):
        path = tmp_path / "bad.yml"
        path.write_text("name: bad\n", encoding="utf-8")
        result = validate_command(str(path))
        assert result.code == 1
        assert "INVALID" in result.stderr

    def test_json_mode_valid(self, tmp_path):
        path = tmp_path / "policy.yml"
        path.write_text(VALID_POLICY_YAML, encoding="utf-8")
        result = validate_command(str(path), {"json": True})
        payload = json.loads(result.stdout)
        assert payload["ok"] is True
        assert payload["data"]["valid"] is True

    def test_json_mode_invalid_includes_errors(self, tmp_path):
        path = tmp_path / "bad.yml"
        path.write_text("name: bad\n", encoding="utf-8")
        result = validate_command(str(path), {"json": True})
        payload = json.loads(result.stdout)
        assert payload["ok"] is False
        assert len(payload["error"]["details"]) > 0

    def test_nonexistent_file_exits_one(self):
        result = validate_command("/nonexistent/policy.yml")
        assert result.code == 1


class TestAuditCommand:
    def _make_trace(self, tmp_path, secret_key=None):
        path = str(tmp_path / "trace.jsonl")
        writer = TraceWriter(path, TraceWriterOptions(secret_key=secret_key) if secret_key else None)
        writer.append(
            TraceEntryInput(
                session_id="s1",
                agent_id="a1",
                tool="shell",
                args={"command": "ls"},
                decision="allow",
                rule_fired=[],
                declared_scope=ScopeDeclaration(),
            )
        )
        writer.append(
            TraceEntryInput(
                session_id="s1",
                agent_id="a1",
                tool="shell",
                args={"command": "rm -rf /"},
                decision="deny",
                rule_fired=["TG01-rm-rf"],
                declared_scope=ScopeDeclaration(),
            )
        )
        return path

    def test_missing_arg_exits_two(self):
        result = audit_command(None, {})
        assert result.code == 2

    def test_lists_all_entries(self, tmp_path):
        path = self._make_trace(tmp_path)
        result = audit_command(path, {})
        assert result.code == 0
        assert "2 of 2 trace entries matched" in result.stdout

    def test_filters_by_decision(self, tmp_path):
        path = self._make_trace(tmp_path)
        result = audit_command(path, {"decision": "deny"})
        assert "1 of 2 trace entries matched" in result.stdout

    def test_invalid_decision_exits_two(self, tmp_path):
        path = self._make_trace(tmp_path)
        result = audit_command(path, {"decision": "maybe"})
        assert result.code == 2

    def test_verify_chain_ok(self, tmp_path):
        path = self._make_trace(tmp_path)
        result = audit_command(path, {"verify-chain": True})
        assert result.code == 0
        assert "Chain OK" in result.stdout

    def test_verify_chain_with_key_file(self, tmp_path):
        key = b"my-secret-key"
        path = self._make_trace(tmp_path, secret_key=key)
        key_file = tmp_path / "key.bin"
        key_file.write_bytes(key)
        result = audit_command(path, {"verify-chain": True, "key-file": str(key_file)})
        assert result.code == 0
        assert "Chain OK" in result.stdout

    def test_verify_chain_unkeyed_trace_fine_even_with_key_file_passed(self, tmp_path):
        """Regression: passing --key-file against a trace that was never hmac-signed must not
        make every legitimate unkeyed entry spuriously fail chain verification."""
        path = self._make_trace(tmp_path)  # unkeyed
        key_file = tmp_path / "key.bin"
        key_file.write_bytes(b"some-key-never-used")
        result = audit_command(path, {"verify-chain": True, "key-file": str(key_file)})
        assert result.code == 0
        assert "Chain OK" in result.stdout

    def test_missing_key_file_reports_clean_error(self, tmp_path):
        path = self._make_trace(tmp_path)
        result = audit_command(path, {"verify-chain": True, "key-file": "/nonexistent/key.bin"})
        assert result.code == 1

    def test_bad_since_value_exits_two_not_crash(self, tmp_path):
        path = self._make_trace(tmp_path)
        result = audit_command(path, {"since": "1s"})  # unsupported unit
        assert result.code == 2

    def test_json_mode_includes_full_entries(self, tmp_path):
        path = self._make_trace(tmp_path)
        result = audit_command(path, {"json": True})
        payload = json.loads(result.stdout)
        assert payload["ok"] is True
        assert payload["data"]["matched"] == 2
        assert "trace_id" in payload["data"]["entries"][0]

    def test_nonexistent_trace_file_exits_one(self, tmp_path):
        result = audit_command(str(tmp_path / "missing.jsonl"), {})
        assert result.code == 1


class TestRunCommand:
    def test_no_command_shows_usage_exit_two(self):
        result = run_command([])
        assert result.code == 2
        assert "Usage:" in result.stderr

    def test_help_flag(self):
        result = run_command(["--help"])
        assert result.code == 0
        assert "Usage:" in result.stdout

    def test_unknown_command_exits_two(self):
        result = run_command(["frobnicate"])
        assert result.code == 2
        assert 'Unknown command "frobnicate"' in result.stderr

    def test_validate_dispatches(self, tmp_path):
        path = tmp_path / "policy.yml"
        path.write_text(VALID_POLICY_YAML, encoding="utf-8")
        result = run_command(["validate", str(path)])
        assert result.code == 0
