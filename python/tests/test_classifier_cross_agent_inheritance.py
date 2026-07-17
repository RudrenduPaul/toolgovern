"""TG05 cross-agent-inheritance classifier tests. Ported in spirit from
packages/toolgovern/test/classifier/cross-agent-inheritance.test.ts -- covers all 6 TG05 rules.
"""

from toolgovern import ScopeDeclaration, ScopeRegistry, SpawnSubAgentParams
from toolgovern.classifier.cross_agent_inheritance import cross_agent_inheritance_rules
from toolgovern.classifier.index import classify


def _fired(ctx):
    result = classify(ctx)
    return result.decision, [r.rule_id for r in result.fired_rules]


class TestUnregisteredSubAgent:
    def test_fires_for_unregistered_agent_with_coordinator(self, ctx_factory):
        registry = ScopeRegistry()
        ctx = ctx_factory(
            {"command": "ls"},
            agent_id="ghost-sub",
            coordinator_id="coordinator-1",
            scope_registry=registry,
        )
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG05-unregistered-sub-agent" in ids

    def test_no_coordinator_id_does_not_fire(self, ctx_factory):
        registry = ScopeRegistry()
        ctx = ctx_factory({"command": "ls"}, agent_id="root-agent", scope_registry=registry)
        decision, ids = _fired(ctx)
        assert "TG05-unregistered-sub-agent" not in ids

    def test_registered_sub_agent_does_not_fire(self, ctx_factory):
        registry = ScopeRegistry()
        registry.register_root_agent("coordinator-1", "s1", ScopeDeclaration(filesystem=["/workspace"]))
        registry.spawn_sub_agent(
            SpawnSubAgentParams(
                coordinator_id="coordinator-1",
                sub_agent_id="sub-1",
                session_id="s1",
                requested_scope=ScopeDeclaration(filesystem=["/workspace"]),
            )
        )
        ctx = ctx_factory(
            {"command": "ls"}, agent_id="sub-1", coordinator_id="coordinator-1", scope_registry=registry
        )
        decision, ids = _fired(ctx)
        assert "TG05-unregistered-sub-agent" not in ids


class TestZeroCapabilitySubAgent:
    def test_fires_for_zero_capability_grant(self, ctx_factory):
        registry = ScopeRegistry()
        registry.register_root_agent("coordinator-1", "s1", ScopeDeclaration())  # empty scope
        registry.spawn_sub_agent(
            SpawnSubAgentParams(
                coordinator_id="coordinator-1",
                sub_agent_id="sub-1",
                session_id="s1",
                requested_scope=ScopeDeclaration(filesystem=["/anything"]),
            )
        )
        ctx = ctx_factory(
            {"command": "ls"}, agent_id="sub-1", coordinator_id="coordinator-1", scope_registry=registry
        )
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG05-zero-capability-sub-agent" in ids

    def test_nonzero_capability_does_not_fire(self, ctx_factory):
        registry = ScopeRegistry()
        registry.register_root_agent("coordinator-1", "s1", ScopeDeclaration(filesystem=["/workspace"]))
        registry.spawn_sub_agent(
            SpawnSubAgentParams(
                coordinator_id="coordinator-1",
                sub_agent_id="sub-1",
                session_id="s1",
                requested_scope=ScopeDeclaration(filesystem=["/workspace"]),
            )
        )
        ctx = ctx_factory(
            {"path": "/workspace/f.txt"},
            agent_id="sub-1",
            coordinator_id="coordinator-1",
            scope_registry=registry,
        )
        decision, ids = _fired(ctx)
        assert "TG05-zero-capability-sub-agent" not in ids


class TestNetworkExceedsGrant:
    def test_fires_when_requested_but_not_granted(self, ctx_factory):
        registry = ScopeRegistry()
        registry.register_root_agent("coordinator-1", "s1", ScopeDeclaration(network=["good.example"]))
        registry.spawn_sub_agent(
            SpawnSubAgentParams(
                coordinator_id="coordinator-1",
                sub_agent_id="sub-1",
                session_id="s1",
                requested_scope=ScopeDeclaration(network=["good.example", "evil.example"]),
            )
        )
        ctx = ctx_factory(
            {"host": "evil.example"}, agent_id="sub-1", coordinator_id="coordinator-1", scope_registry=registry
        )
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG05-network-exceeds-grant" in ids


class TestFilesystemExceedsGrant:
    def test_fires_when_requested_but_not_granted(self, ctx_factory):
        registry = ScopeRegistry()
        registry.register_root_agent("coordinator-1", "s1", ScopeDeclaration(filesystem=["/workspace"]))
        registry.spawn_sub_agent(
            SpawnSubAgentParams(
                coordinator_id="coordinator-1",
                sub_agent_id="sub-1",
                session_id="s1",
                requested_scope=ScopeDeclaration(filesystem=["/workspace", "/etc"]),
            )
        )
        ctx = ctx_factory(
            {"path": "/etc/passwd"}, agent_id="sub-1", coordinator_id="coordinator-1", scope_registry=registry
        )
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG05-filesystem-exceeds-grant" in ids


class TestCredentialExceedsGrant:
    def test_fires_when_requested_but_not_granted(self, ctx_factory):
        registry = ScopeRegistry()
        registry.register_root_agent("coordinator-1", "s1", ScopeDeclaration(credentials=["aws"]))
        registry.spawn_sub_agent(
            SpawnSubAgentParams(
                coordinator_id="coordinator-1",
                sub_agent_id="sub-1",
                session_id="s1",
                requested_scope=ScopeDeclaration(credentials=["aws", "gcp"]),
            )
        )
        ctx = ctx_factory(
            {"credential": "gcp"}, agent_id="sub-1", coordinator_id="coordinator-1", scope_registry=registry
        )
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG05-credential-exceeds-grant" in ids


class TestCoordinatorScopeShrunk:
    def test_fires_when_coordinator_no_longer_covers_path(self, ctx_factory):
        registry = ScopeRegistry()
        registry.register_root_agent("coordinator-1", "s1", ScopeDeclaration(filesystem=["/workspace"]))
        registry.spawn_sub_agent(
            SpawnSubAgentParams(
                coordinator_id="coordinator-1",
                sub_agent_id="sub-1",
                session_id="s1",
                requested_scope=ScopeDeclaration(filesystem=["/workspace"]),
            )
        )
        # Coordinator's own scope shrinks after the sub-agent was spawned.
        registry.register_root_agent("coordinator-1", "s1", ScopeDeclaration(filesystem=["/other"]))
        ctx = ctx_factory(
            {"path": "/workspace/file.txt"},
            agent_id="sub-1",
            coordinator_id="coordinator-1",
            scope_registry=registry,
        )
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG05-coordinator-scope-shrunk" in ids

    def test_no_shrink_does_not_fire(self, ctx_factory):
        registry = ScopeRegistry()
        registry.register_root_agent("coordinator-1", "s1", ScopeDeclaration(filesystem=["/workspace"]))
        registry.spawn_sub_agent(
            SpawnSubAgentParams(
                coordinator_id="coordinator-1",
                sub_agent_id="sub-1",
                session_id="s1",
                requested_scope=ScopeDeclaration(filesystem=["/workspace"]),
            )
        )
        ctx = ctx_factory(
            {"path": "/workspace/file.txt"},
            agent_id="sub-1",
            coordinator_id="coordinator-1",
            scope_registry=registry,
        )
        decision, ids = _fired(ctx)
        assert "TG05-coordinator-scope-shrunk" not in ids


def test_rule_registry_has_six_tg05_rules():
    assert len(cross_agent_inheritance_rules) == 6
    assert len({r.id for r in cross_agent_inheritance_rules}) == 6
