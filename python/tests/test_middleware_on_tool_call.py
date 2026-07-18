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
    PendingApprovalNotResolvableError,
    PendingApprovalRegistry,
    ResolvePendingInput,
    ScopeDeclaration,
    ScopeRegistry,
    ToolDefinition,
    ToolGovernDenialError,
    TraceWriter,
    govern_tool,
    read_trace,
    resume_pending_approval,
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


class TestPendingApprovalsDurableRegistry:
    """pending_approvals wiring, ported in spirit from onToolCall.test.ts's
    'pendingApprovals (durable, resumable approval registry)' describe block."""

    def test_registers_a_durable_pending_approval_before_the_sync_handler_runs(self):
        registry = PendingApprovalRegistry()
        seen = {}

        def handler(info):
            seen["pending_id"] = info.pending_id
            assert info.pending_id is not None
            assert registry.get(info.pending_id).status == "pending"
            return True

        tool = _echo_tool()
        gated = govern_tool(
            tool,
            GovernToolOptions(
                scope=ScopeDeclaration(),
                pending_approvals=registry,
                on_approval_required=handler,
            ),
        )
        gated.execute({"command": "sudo apt-get update"})
        assert seen["pending_id"] is not None

    def test_reflects_the_sync_paths_outcome_back_into_the_registry(self):
        registry = PendingApprovalRegistry()
        seen = {}
        tool = _echo_tool()
        gated = govern_tool(
            tool,
            GovernToolOptions(
                scope=ScopeDeclaration(),
                pending_approvals=registry,
                on_decision=lambda info: seen.setdefault("pending_id", info.pending_id),
                on_approval_required=lambda info: ApprovalOutcome(
                    approved=True, approved_by="alice@example.com"
                ),
            ),
        )
        gated.execute({"command": "sudo apt-get update"})

        entry = registry.get(seen["pending_id"])
        assert entry.status == "resolved"
        assert entry.resolution.decision == "allow"
        assert entry.resolution.approved_by == "alice@example.com"

    def test_a_genuine_sync_decision_is_terminal_later_resolve_pending_gets_already_resolved(self):
        registry = PendingApprovalRegistry()
        seen = {}
        tool = _echo_tool()
        gated = govern_tool(
            tool,
            GovernToolOptions(
                scope=ScopeDeclaration(),
                pending_approvals=registry,
                on_decision=lambda info: seen.setdefault("pending_id", info.pending_id),
                # A real, answering handler -- explicitly denies.
                on_approval_required=lambda info: False,
            ),
        )
        with pytest.raises(ToolGovernDenialError):
            gated.execute({"command": "sudo apt-get update"})

        outcome = registry.resolve_pending(
            seen["pending_id"],
            ResolvePendingInput(decision="allow", approved_by="late-approver@example.com"),
        )
        assert outcome.status == "already-resolved"
        assert outcome.final_decision == "deny"

    def test_fail_closed_default_leaves_the_registry_entry_pending_for_later_resolution(self):
        # Case 1: no on_approval_required at all.
        registry = PendingApprovalRegistry()
        seen = {}
        tool = _echo_tool()
        gated_no_handler = govern_tool(
            tool,
            GovernToolOptions(
                scope=ScopeDeclaration(),
                pending_approvals=registry,
                on_decision=lambda info: seen.setdefault("pending_id", info.pending_id),
            ),
        )
        with pytest.raises(ToolGovernDenialError):
            gated_no_handler.execute({"command": "sudo apt-get update"})
        assert registry.get(seen["pending_id"]).status == "pending"

        # Case 2: a handler that times out.
        registry2 = PendingApprovalRegistry()
        seen2 = {}

        def slow_handler(info):
            time.sleep(2)
            return True

        gated_timeout = govern_tool(
            _echo_tool(),
            GovernToolOptions(
                scope=ScopeDeclaration(),
                pending_approvals=registry2,
                approval_timeout_ms=50,
                on_approval_required=slow_handler,
                on_decision=lambda info: seen2.setdefault("pending_id", info.pending_id),
            ),
        )
        with pytest.raises(ToolGovernDenialError):
            gated_timeout.execute({"command": "sudo apt-get update"})
        assert registry2.get(seen2["pending_id"]).status == "pending"

        # Case 3: a handler that raises.
        registry3 = PendingApprovalRegistry()
        seen3 = {}

        def bad_handler(info):
            raise RuntimeError("handler blew up")

        gated_throws = govern_tool(
            _echo_tool(),
            GovernToolOptions(
                scope=ScopeDeclaration(),
                pending_approvals=registry3,
                on_approval_required=bad_handler,
                on_decision=lambda info: seen3.setdefault("pending_id", info.pending_id),
            ),
        )
        with pytest.raises(ToolGovernDenialError):
            gated_throws.execute({"command": "sudo apt-get update"})
        assert registry3.get(seen3["pending_id"]).status == "pending"

    def test_no_pending_approvals_registry_configured_no_regression(self):
        tool = _echo_tool()
        gated = govern_tool(
            tool,
            GovernToolOptions(scope=ScopeDeclaration(), on_approval_required=lambda info: True),
        )
        result = gated.execute({"command": "sudo apt-get update"})
        assert result["ok"] is True

    def test_an_allow_decision_does_not_register_a_pending_approval_at_all(self):
        registry = PendingApprovalRegistry()
        seen = {"pending_id": "unset"}
        tool = _echo_tool()
        gated = govern_tool(
            tool,
            GovernToolOptions(
                scope=ScopeDeclaration(),
                pending_approvals=registry,
                on_decision=lambda info: seen.__setitem__("pending_id", info.pending_id),
            ),
        )
        gated.execute({"command": "ls"})
        assert seen["pending_id"] is None


class TestResumePendingApproval:
    """Closing the loop for the async-resume path -- ported in spirit from onToolCall.test.ts's
    'resumePendingApproval()' describe block."""

    def test_executes_the_tool_once_resolved_to_allow(self):
        registry = PendingApprovalRegistry()
        seen = {}
        tool = _echo_tool()
        gated = govern_tool(
            tool,
            GovernToolOptions(
                scope=ScopeDeclaration(),
                pending_approvals=registry,
                on_decision=lambda info: seen.setdefault("pending_id", info.pending_id),
            ),
        )
        with pytest.raises(ToolGovernDenialError):
            gated.execute({"command": "sudo apt-get update"})

        result = resume_pending_approval(
            tool,
            registry,
            seen["pending_id"],
            ResolvePendingInput(decision="allow", approved_by="alice@example.com"),
        )
        assert result["ok"] is True

    def test_populates_approved_by_end_to_end_on_the_async_resume_trace_entry(self, tmp_path):
        from toolgovern.middleware.on_tool_call import ResumePendingApprovalOptions

        trace_path = str(tmp_path / "trace.jsonl")
        trace = TraceWriter(trace_path)
        registry = PendingApprovalRegistry()
        seen = {}
        tool = _echo_tool()
        gated = govern_tool(
            tool,
            GovernToolOptions(
                scope=ScopeDeclaration(),
                pending_approvals=registry,
                trace=trace,
                agent_id="coordinator",
                session_id="s1",
                on_decision=lambda info: seen.setdefault("pending_id", info.pending_id),
            ),
        )
        with pytest.raises(ToolGovernDenialError):
            gated.execute({"command": "sudo apt-get update"})

        resume_pending_approval(
            tool,
            registry,
            seen["pending_id"],
            ResolvePendingInput(decision="allow", approved_by="alice@example.com"),
            ResumePendingApprovalOptions(trace=trace),
        )

        entries = read_trace(trace_path)
        # Two real trace entries: the synchronous path's fail-closed deny (at the original call),
        # and the async-resume path's allow (once a human actually approved it later).
        assert len(entries) == 2
        assert entries[0].decision == "deny"
        assert entries[1].decision == "allow"
        assert entries[1].approved_by == "alice@example.com"
        assert entries[1].prior_trace_id == entries[0].trace_id

    def test_denies_when_resolution_reclassifies_edited_args_to_a_still_risky_call(self):
        registry = PendingApprovalRegistry()
        seen = {}
        calls = []
        tool = _echo_tool(calls)
        gated = govern_tool(
            tool,
            GovernToolOptions(
                scope=ScopeDeclaration(),
                pending_approvals=registry,
                on_decision=lambda info: seen.setdefault("pending_id", info.pending_id),
            ),
        )
        with pytest.raises(ToolGovernDenialError):
            gated.execute({"command": "sudo apt-get update"})

        with pytest.raises(ToolGovernDenialError):
            resume_pending_approval(
                tool,
                registry,
                seen["pending_id"],
                ResolvePendingInput(
                    decision="allow",
                    approved_by="alice@example.com",
                    edited_args={"command": "rm -rf /"},
                ),
            )
        assert calls == []

    def test_executes_with_the_edited_arguments_when_the_edit_remains_clean(self):
        registry = PendingApprovalRegistry()
        seen = {}
        tool = _echo_tool()
        gated = govern_tool(
            tool,
            GovernToolOptions(
                scope=ScopeDeclaration(),
                pending_approvals=registry,
                on_decision=lambda info: seen.setdefault("pending_id", info.pending_id),
            ),
        )
        with pytest.raises(ToolGovernDenialError):
            gated.execute({"command": "sudo apt-get update"})

        result = resume_pending_approval(
            tool,
            registry,
            seen["pending_id"],
            ResolvePendingInput(decision="allow", edited_args={"command": "ls"}),
        )
        assert result["args"] == {"command": "ls"}

    def test_raises_pending_approval_not_resolvable_error_for_unrecognized_id(self):
        calls = []
        tool = _echo_tool(calls)
        registry = PendingApprovalRegistry()

        with pytest.raises(PendingApprovalNotResolvableError):
            resume_pending_approval(
                tool, registry, "never-registered", ResolvePendingInput(decision="allow")
            )
        assert calls == []

    def test_resolving_by_an_alias_registered_after_the_original_call_still_resumes(self):
        registry = PendingApprovalRegistry()
        seen = {}
        tool = _echo_tool()
        gated = govern_tool(
            tool,
            GovernToolOptions(
                scope=ScopeDeclaration(),
                pending_approvals=registry,
                on_decision=lambda info: seen.setdefault("pending_id", info.pending_id),
            ),
        )
        with pytest.raises(ToolGovernDenialError):
            gated.execute({"command": "sudo apt-get update"})

        registry.register_alias(seen["pending_id"], "webhook-thread-id-v2")
        result = resume_pending_approval(
            tool, registry, "webhook-thread-id-v2", ResolvePendingInput(decision="allow")
        )
        assert result["ok"] is True
