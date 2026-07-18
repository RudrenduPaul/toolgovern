"""Tests for govern_tool() -- the core middleware hook. Ported in spirit from
packages/toolgovern/test/middleware/onToolCall.test.ts: approval flow, fail-closed timeout,
idempotency cache, trace integration, agent-identity format validation.
"""

import time

import pytest

from toolgovern import (
    ApprovalOutcome,
    GovernToolOptions,
    IdempotencyOptions,
    InvalidAgentIdError,
    ScopeDeclaration,
    ScopeRegistry,
    ToolDefinition,
    ToolGovernDenialError,
    TraceWriter,
    govern_tool,
    read_trace,
)


def _echo_tool(calls=None):
    def execute(args):
        if calls is not None:
            calls.append(args)
        return {"ok": True, "args": args}

    return ToolDefinition(name="shell", execute=execute)


class TestAllowDenyFlow:
    def test_allows_benign_call(self):
        tool = _echo_tool()
        gated = govern_tool(tool, GovernToolOptions(scope=ScopeDeclaration()))
        result = gated.execute({"command": "ls"})
        assert result["ok"] is True

    def test_denies_and_raises(self):
        tool = _echo_tool()
        gated = govern_tool(tool, GovernToolOptions(scope=ScopeDeclaration()))
        with pytest.raises(ToolGovernDenialError) as exc_info:
            gated.execute({"command": "rm -rf /"})
        assert "TG01-rm-rf" in str(exc_info.value)

    def test_underlying_tool_never_runs_on_deny(self):
        calls = []
        tool = _echo_tool(calls)
        gated = govern_tool(tool, GovernToolOptions(scope=ScopeDeclaration()))
        with pytest.raises(ToolGovernDenialError):
            gated.execute({"command": "rm -rf /"})
        assert calls == []


class TestApprovalFlow:
    def test_approved_call_executes(self):
        tool = _echo_tool()
        gated = govern_tool(
            tool,
            GovernToolOptions(
                scope=ScopeDeclaration(),
                on_approval_required=lambda info: True,
            ),
        )
        result = gated.execute({"command": "sudo apt-get update"})
        assert result["ok"] is True

    def test_denied_approval_raises(self):
        tool = _echo_tool()
        gated = govern_tool(
            tool,
            GovernToolOptions(scope=ScopeDeclaration(), on_approval_required=lambda info: False),
        )
        with pytest.raises(ToolGovernDenialError):
            gated.execute({"command": "sudo apt-get update"})

    def test_no_handler_fails_closed(self):
        tool = _echo_tool()
        gated = govern_tool(tool, GovernToolOptions(scope=ScopeDeclaration()))
        with pytest.raises(ToolGovernDenialError):
            gated.execute({"command": "sudo apt-get update"})

    def test_handler_timeout_fails_closed(self):
        def slow_handler(info):
            time.sleep(2)
            return True

        tool = _echo_tool()
        gated = govern_tool(
            tool,
            GovernToolOptions(
                scope=ScopeDeclaration(),
                on_approval_required=slow_handler,
                approval_timeout_ms=50,
            ),
        )
        with pytest.raises(ToolGovernDenialError):
            gated.execute({"command": "sudo apt-get update"})

    def test_throwing_handler_fails_closed_not_crash(self):
        def bad_handler(info):
            raise RuntimeError("handler blew up")

        tool = _echo_tool()
        gated = govern_tool(
            tool, GovernToolOptions(scope=ScopeDeclaration(), on_approval_required=bad_handler)
        )
        with pytest.raises(ToolGovernDenialError):
            gated.execute({"command": "sudo apt-get update"})

    def test_approval_outcome_records_approved_by(self, tmp_path):
        trace_path = str(tmp_path / "trace.jsonl")
        trace = TraceWriter(trace_path)
        tool = _echo_tool()
        gated = govern_tool(
            tool,
            GovernToolOptions(
                scope=ScopeDeclaration(),
                on_approval_required=lambda info: ApprovalOutcome(approved=True, approved_by="reviewer@example.com"),
                trace=trace,
            ),
        )
        gated.execute({"command": "sudo apt-get update"})
        entries = read_trace(trace_path)
        assert entries[0].approved_by == "reviewer@example.com"


class TestTraceIntegration:
    def test_allow_writes_trace_entry(self, tmp_path):
        trace_path = str(tmp_path / "trace.jsonl")
        trace = TraceWriter(trace_path)
        tool = _echo_tool()
        gated = govern_tool(tool, GovernToolOptions(scope=ScopeDeclaration(), trace=trace))
        gated.execute({"command": "ls"})
        entries = read_trace(trace_path)
        assert len(entries) == 1
        assert entries[0].decision == "allow"

    def test_deny_still_writes_trace_entry(self, tmp_path):
        trace_path = str(tmp_path / "trace.jsonl")
        trace = TraceWriter(trace_path)
        tool = _echo_tool()
        gated = govern_tool(tool, GovernToolOptions(scope=ScopeDeclaration(), trace=trace))
        with pytest.raises(ToolGovernDenialError):
            gated.execute({"command": "rm -rf /"})
        entries = read_trace(trace_path)
        assert len(entries) == 1
        assert entries[0].decision == "deny"
        assert "TG01-rm-rf" in entries[0].rule_fired

    def test_throwing_approval_handler_still_writes_trace(self, tmp_path):
        """Regression test matching docs/security-model.md finding #3: a throwing approval
        handler must not skip the trace write."""
        trace_path = str(tmp_path / "trace.jsonl")
        trace = TraceWriter(trace_path)

        def bad_handler(info):
            raise RuntimeError("handler blew up")

        tool = _echo_tool()
        gated = govern_tool(
            tool,
            GovernToolOptions(
                scope=ScopeDeclaration(), on_approval_required=bad_handler, trace=trace
            ),
        )
        with pytest.raises(ToolGovernDenialError):
            gated.execute({"command": "sudo apt-get update"})
        entries = read_trace(trace_path)
        assert len(entries) == 1
        assert entries[0].decision == "deny"


class TestAgentIdentity:
    def test_invalid_agent_id_raises_at_wrap_time(self):
        tool = _echo_tool()
        with pytest.raises(InvalidAgentIdError):
            govern_tool(tool, GovernToolOptions(scope=ScopeDeclaration(), agent_id=""))

    def test_control_character_agent_id_raises(self):
        tool = _echo_tool()
        with pytest.raises(InvalidAgentIdError):
            govern_tool(tool, GovernToolOptions(scope=ScopeDeclaration(), agent_id="agent\x00evil"))

    def test_explicit_agent_id_source_recorded(self, tmp_path):
        trace_path = str(tmp_path / "trace.jsonl")
        trace = TraceWriter(trace_path)
        tool = _echo_tool()
        gated = govern_tool(
            tool, GovernToolOptions(scope=ScopeDeclaration(), agent_id="my-agent", trace=trace)
        )
        gated.execute({"command": "ls"})
        entries = read_trace(trace_path)
        assert entries[0].agent_id == "my-agent"
        assert entries[0].agent_id_source == "explicit"

    def test_fallback_agent_id_source_recorded(self, tmp_path):
        trace_path = str(tmp_path / "trace.jsonl")
        trace = TraceWriter(trace_path)
        tool = _echo_tool()
        gated = govern_tool(tool, GovernToolOptions(scope=ScopeDeclaration(), trace=trace))
        gated.execute({"command": "ls"})
        entries = read_trace(trace_path)
        assert entries[0].agent_id == "default-agent"
        assert entries[0].agent_id_source == "fallback"


class TestScopeRegistryIntegration:
    def test_sub_agent_gated_by_coordinator_grant(self):
        registry = ScopeRegistry()
        tool = _echo_tool()
        gated = govern_tool(
            tool,
            GovernToolOptions(
                scope=ScopeDeclaration(filesystem=["/etc"]),  # what the sub-agent itself requests
                agent_id="sub-1",
                coordinator_id="coordinator-1",
                scope_registry=registry,
            ),
        )
        # coordinator-1 was never registered -> default-deny empty scope -> zero capability.
        with pytest.raises(ToolGovernDenialError):
            gated.execute({"path": "/etc/passwd", "operation": "read"})


class TestIdempotency:
    def test_disabled_by_default_runs_every_time(self):
        calls = []
        tool = _echo_tool(calls)
        gated = govern_tool(tool, GovernToolOptions(scope=ScopeDeclaration()))
        gated.execute({"command": "ls"})
        gated.execute({"command": "ls"})
        assert len(calls) == 2

    def test_enabled_dedupes_identical_calls(self):
        calls = []
        tool = _echo_tool(calls)
        gated = govern_tool(
            tool,
            GovernToolOptions(scope=ScopeDeclaration(), idempotency=IdempotencyOptions(enabled=True, ttl_ms=60_000)),
        )
        gated.execute({"command": "ls"})
        gated.execute({"command": "ls"})
        assert len(calls) == 1

    def test_different_args_are_not_deduped(self):
        calls = []
        tool = _echo_tool(calls)
        gated = govern_tool(
            tool,
            GovernToolOptions(scope=ScopeDeclaration(), idempotency=IdempotencyOptions(enabled=True)),
        )
        gated.execute({"command": "ls a"})
        gated.execute({"command": "ls b"})
        assert len(calls) == 2

    def test_failed_execution_is_retryable(self):
        attempt = {"count": 0}

        def flaky_execute(args):
            attempt["count"] += 1
            if attempt["count"] == 1:
                raise RuntimeError("transient failure")
            return {"ok": True}

        tool = ToolDefinition(name="shell", execute=flaky_execute)
        gated = govern_tool(
            tool,
            GovernToolOptions(scope=ScopeDeclaration(), idempotency=IdempotencyOptions(enabled=True)),
        )
        with pytest.raises(RuntimeError):
            gated.execute({"command": "ls"})
        result = gated.execute({"command": "ls"})
        assert result["ok"] is True
        assert attempt["count"] == 2


class TestOnToolResult:
    def test_transforms_success_result(self):
        tool = _echo_tool()
        gated = govern_tool(
            tool,
            GovernToolOptions(scope=ScopeDeclaration(), on_tool_result=lambda result, ctx: {"wrapped": result}),
        )
        result = gated.execute({"command": "ls"})
        assert result["wrapped"]["ok"] is True

    def test_transforms_raised_error(self):
        def failing_execute(args):
            raise RuntimeError("boom")

        tool = ToolDefinition(name="shell", execute=failing_execute)
        gated = govern_tool(
            tool,
            GovernToolOptions(
                scope=ScopeDeclaration(),
                on_tool_result=lambda result, ctx: {"error": str(result)} if isinstance(result, Exception) else result,
            ),
        )
        result = gated.execute({"command": "ls"})
        assert result["error"] == "boom"


class TestDnsResolutionThroughGovernTool:
    """TG03-dns-resolves-private exercised through the real govern_tool() call chain, against the
    real OS resolver (not mocked) -- proves the fix is actually wired into the classify() call
    govern_tool() makes, not just correct in isolation. Python's govern_tool() is synchronous
    end-to-end (see on_tool_call.py's module docstring), so no separate async entry point was
    needed here, unlike the TypeScript port's classifyAsync()."""

    def _http_tool(self, calls=None):
        def execute(args):
            if calls is not None:
                calls.append(args)
            return {"ok": True, "host": args.get("host")}

        return ToolDefinition(name="http.get", execute=execute)

    def test_denies_a_call_whose_hostname_resolves_to_loopback(self):
        calls = []
        tool = self._http_tool(calls)
        gated = govern_tool(
            tool, GovernToolOptions(scope=ScopeDeclaration(network=["other.example"]))
        )
        with pytest.raises(ToolGovernDenialError) as exc_info:
            gated.execute({"host": "localhost"})
        assert "TG03-dns-resolves-private" in str(exc_info.value)
        assert calls == []

    def test_the_denial_carries_the_dns_resolves_private_rule_id_in_fired_rules(self):
        tool = self._http_tool()
        gated = govern_tool(
            tool, GovernToolOptions(scope=ScopeDeclaration(network=["other.example"]))
        )
        try:
            gated.execute({"host": "localhost"})
            pytest.fail("expected govern_tool to raise for a hostname resolving to loopback")
        except ToolGovernDenialError as error:
            rule_ids = [r.rule_id for r in error.decision_info.fired_rules]
            assert "TG03-dns-resolves-private" in rule_ids
