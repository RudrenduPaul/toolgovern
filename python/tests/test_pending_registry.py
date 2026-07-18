"""Tests for PendingApprovalRegistry -- ported in spirit from
packages/toolgovern/test/approval/pending-registry.test.ts: register -> resolve happy path,
resolve-by-alias after alias rewrite, edited-args re-classification blocking a still-risky edit,
the resume-token bypass this guards against (langgraph#8169), and expiry.
"""

import pytest

from toolgovern import (
    PendingApprovalAliasConflictError,
    PendingApprovalRegistry,
    ResolvePendingInput,
    RuleMatch,
    ScopeDeclaration,
    UnknownPendingApprovalError,
)

SCOPE = ScopeDeclaration(network=False, filesystem=["./workspace"], credentials=[])


def _make_registry(**overrides):
    counter = {"n": 0}

    def id_factory():
        counter["n"] += 1
        return f"pending-{counter['n']}"

    kwargs = {"id_factory": id_factory}
    kwargs.update(overrides)
    return PendingApprovalRegistry(**kwargs)


def _sudo_fired_rules():
    return [
        RuleMatch(
            rule_id="TG01-sudo",
            category="TG01",
            decision="require-approval",
            reason="sudo invocation",
            matched_argument="command",
        )
    ]


class TestRegisterResolveHappyPath:
    def test_registers_and_resolves_to_allow(self):
        registry = _make_registry()
        pending_id = registry.register_pending(
            agent_id="agent-1",
            session_id="session-1",
            tool="bash",
            args={"command": "sudo apt-get update"},
            scope=SCOPE,
            fired_rules=_sudo_fired_rules(),
        )

        assert pending_id == "pending-1"
        assert registry.get(pending_id).status == "pending"

        outcome = registry.resolve_pending(
            pending_id, ResolvePendingInput(decision="allow", approved_by="alice@example.com")
        )

        assert outcome.status == "resolved"
        assert outcome.final_decision == "allow"
        assert outcome.approved_by == "alice@example.com"
        assert outcome.args == {"command": "sudo apt-get update"}
        assert registry.get(pending_id).status == "resolved"
        assert registry.get(pending_id).resolution.approved_by == "alice@example.com"

    def test_resolves_to_deny(self):
        registry = _make_registry()
        pending_id = registry.register_pending(
            agent_id="agent-1",
            session_id="session-1",
            tool="bash",
            args={"command": "sudo apt-get update"},
            scope=SCOPE,
            fired_rules=_sudo_fired_rules(),
        )

        outcome = registry.resolve_pending(
            pending_id, ResolvePendingInput(decision="deny", approved_by="bob@example.com")
        )
        assert outcome.status == "resolved"
        assert outcome.final_decision == "deny"

    def test_second_resolve_returns_already_resolved_not_a_fresh_decision(self):
        registry = _make_registry()
        pending_id = registry.register_pending(
            agent_id="agent-1",
            session_id="session-1",
            tool="bash",
            args={"command": "sudo apt-get update"},
            scope=SCOPE,
            fired_rules=_sudo_fired_rules(),
        )

        registry.resolve_pending(
            pending_id, ResolvePendingInput(decision="allow", approved_by="alice@example.com")
        )
        second = registry.resolve_pending(
            pending_id, ResolvePendingInput(decision="deny", approved_by="mallory@example.com")
        )

        assert second.status == "already-resolved"
        # The FIRST resolution's outcome wins -- a later call can never flip it.
        assert second.final_decision == "allow"
        assert second.approved_by == "alice@example.com"


class TestResolveByAliasAfterAliasRewrite:
    """microsoft/agent-framework#6908 ("Python: Fix AG-UI approval thread aliases")."""

    def test_resolves_by_an_alias_registered_after_the_original_id(self):
        registry = _make_registry()
        pending_id = registry.register_pending(
            agent_id="agent-1",
            session_id="thread-original",
            tool="bash",
            args={"command": "sudo apt-get update"},
            scope=SCOPE,
            fired_rules=_sudo_fired_rules(),
        )

        # A stateful provider rewrites the thread id mid-stream; the caller learns the new id and
        # records it as an alias for the same pending approval.
        registry.register_alias(pending_id, "thread-rewritten-by-provider")

        by_original = registry.get(pending_id)
        by_alias = registry.get("thread-rewritten-by-provider")
        assert by_original.pending_id == pending_id
        assert by_alias.pending_id == pending_id
        assert "thread-rewritten-by-provider" in by_alias.aliases

        # Resolving with the client's ORIGINAL thread id must still work even though the provider
        # has since rewritten it -- this is the exact failure mode #6908 fixed.
        outcome = registry.resolve_pending(
            pending_id, ResolvePendingInput(decision="allow", approved_by="alice@example.com")
        )
        assert outcome.status == "resolved"

    def test_resolving_by_alias_consumes_the_shared_entry_no_double_resolution(self):
        registry = _make_registry()
        pending_id = registry.register_pending(
            agent_id="agent-1",
            session_id="thread-original",
            tool="bash",
            args={"command": "sudo apt-get update"},
            scope=SCOPE,
            fired_rules=_sudo_fired_rules(),
        )
        registry.register_alias(pending_id, "thread-rewritten-by-provider")

        resolved_by_alias = registry.resolve_pending(
            "thread-rewritten-by-provider",
            ResolvePendingInput(decision="allow", approved_by="alice@example.com"),
        )
        assert resolved_by_alias.status == "resolved"

        # Now resolving by the ORIGINAL id (the shared entry was already consumed via the alias)
        # must report already-resolved, not silently re-decide or re-execute.
        resolved_again = registry.resolve_pending(pending_id, ResolvePendingInput(decision="deny"))
        assert resolved_again.status == "already-resolved"
        assert resolved_again.final_decision == "allow"

    def test_register_alias_raises_for_unrecognized_pending_id(self):
        registry = _make_registry()
        with pytest.raises(UnknownPendingApprovalError):
            registry.register_alias("does-not-exist", "some-alias")

    def test_register_alias_raises_when_alias_already_refers_to_a_different_pending_approval(self):
        registry = _make_registry()
        first = registry.register_pending(
            agent_id="agent-1",
            session_id="s1",
            tool="bash",
            args={"command": "a"},
            scope=SCOPE,
            fired_rules=_sudo_fired_rules(),
        )
        second = registry.register_pending(
            agent_id="agent-1",
            session_id="s2",
            tool="bash",
            args={"command": "b"},
            scope=SCOPE,
            fired_rules=_sudo_fired_rules(),
        )
        registry.register_alias(first, "shared-alias")
        with pytest.raises(PendingApprovalAliasConflictError):
            registry.register_alias(second, "shared-alias")


class TestEditedArgsReclassification:
    """resolve_pending() must never bypass the classifier a second time."""

    def test_denies_edited_args_that_would_themselves_trigger_a_deny_even_after_approval(self):
        registry = _make_registry()
        pending_id = registry.register_pending(
            agent_id="agent-1",
            session_id="s1",
            tool="bash",
            args={"command": "sudo apt-get update"},
            scope=SCOPE,
            fired_rules=_sudo_fired_rules(),
        )

        # The human clicks "approve", but edits the arguments to something the classifier itself
        # would deny outright (TG01-rm-rf) -- approving must not smuggle this through.
        outcome = registry.resolve_pending(
            pending_id,
            ResolvePendingInput(
                decision="allow",
                approved_by="alice@example.com",
                edited_args={"command": "rm -rf /"},
            ),
        )

        assert outcome.status == "resolved"
        assert outcome.final_decision == "deny"
        assert outcome.args == {"command": "rm -rf /"}
        assert "TG01-rm-rf" in [r.rule_id for r in outcome.fired_rules]
        # The registry's own record must reflect the OVERRIDDEN decision, not the human's raw
        # input -- an auditor reading this entry later must see "denied", not "approved".
        assert registry.get(pending_id).resolution.decision == "deny"

    def test_allows_edited_args_that_remain_clean(self):
        registry = _make_registry()
        pending_id = registry.register_pending(
            agent_id="agent-1",
            session_id="s1",
            tool="bash",
            args={"command": "sudo apt-get update"},
            scope=SCOPE,
            fired_rules=_sudo_fired_rules(),
        )

        outcome = registry.resolve_pending(
            pending_id,
            ResolvePendingInput(
                decision="allow",
                approved_by="alice@example.com",
                edited_args={"command": "ls ./workspace"},
            ),
        )

        assert outcome.status == "resolved"
        assert outcome.final_decision == "allow"
        assert outcome.args == {"command": "ls ./workspace"}

    def test_applies_the_same_rule_overrides_captured_at_registration_time(self):
        registry = _make_registry()
        pending_id = registry.register_pending(
            agent_id="agent-1",
            session_id="s1",
            tool="bash",
            args={"command": "sudo apt-get update"},
            scope=SCOPE,
            fired_rules=_sudo_fired_rules(),
            disabled_rules=["TG01-rm-rf"],
        )

        outcome = registry.resolve_pending(
            pending_id,
            ResolvePendingInput(decision="allow", edited_args={"command": "rm -rf /"}),
        )

        assert outcome.final_decision == "allow"

    def test_deny_with_edited_args_does_not_trigger_reclassification_at_all(self):
        calls = {"count": 0}

        def spy_reclassify(ctx, options):
            calls["count"] += 1
            from toolgovern import classify

            return classify(ctx, options)

        registry = _make_registry(reclassify=spy_reclassify)
        pending_id = registry.register_pending(
            agent_id="agent-1",
            session_id="s1",
            tool="bash",
            args={"command": "sudo apt-get update"},
            scope=SCOPE,
            fired_rules=_sudo_fired_rules(),
        )

        outcome = registry.resolve_pending(
            pending_id,
            ResolvePendingInput(decision="deny", edited_args={"command": "ls ./workspace"}),
        )

        assert outcome.final_decision == "deny"
        assert calls["count"] == 0


class TestResumeTokenBypassLangGraph8169:
    def test_resolve_pending_never_creates_a_new_pending_approval_for_unrecognized_id(self):
        registry = _make_registry()
        outcome = registry.resolve_pending(
            "attacker-chosen-id",
            ResolvePendingInput(decision="allow", approved_by="mallory@example.com"),
        )

        assert outcome.status == "not-found"
        assert outcome.final_decision is None
        assert registry.get("attacker-chosen-id") is None

        second_attempt = registry.resolve_pending(
            "attacker-chosen-id", ResolvePendingInput(decision="allow")
        )
        assert second_attempt.status == "not-found"

    def test_pending_id_is_always_server_generated(self):
        registry = _make_registry()
        kwargs = dict(
            agent_id="agent-1",
            session_id="s1",
            tool="bash",
            args={"command": "ls"},
            scope=SCOPE,
            fired_rules=[],
        )
        first = registry.register_pending(**kwargs)
        second = registry.register_pending(**kwargs)
        assert first == "pending-1"
        assert second == "pending-2"
        assert first != second


class TestExpiry:
    def test_an_expired_pending_approval_cannot_be_resolved(self):
        now = {"value": 1_000_000.0}
        registry = _make_registry(now=lambda: now["value"])
        pending_id = registry.register_pending(
            agent_id="agent-1",
            session_id="s1",
            tool="bash",
            args={"command": "sudo apt-get update"},
            scope=SCOPE,
            fired_rules=_sudo_fired_rules(),
            ttl_ms=1_000,
        )

        now["value"] += 5_000
        outcome = registry.resolve_pending(pending_id, ResolvePendingInput(decision="allow"))
        assert outcome.status == "expired"
        assert registry.get(pending_id).status == "expired"

    def test_with_no_ttl_never_expires_on_its_own(self):
        now = {"value": 1_000_000.0}
        registry = _make_registry(now=lambda: now["value"])
        pending_id = registry.register_pending(
            agent_id="agent-1",
            session_id="s1",
            tool="bash",
            args={"command": "sudo apt-get update"},
            scope=SCOPE,
            fired_rules=_sudo_fired_rules(),
        )

        now["value"] += 1_000_000_000
        outcome = registry.resolve_pending(pending_id, ResolvePendingInput(decision="allow"))
        assert outcome.status == "resolved"


class TestGet:
    def test_returns_none_for_unregistered_id(self):
        registry = _make_registry()
        assert registry.get("never-registered") is None
