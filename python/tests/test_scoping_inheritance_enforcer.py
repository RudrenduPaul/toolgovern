"""Tests for compute_inherited_scope / ScopeRegistry -- default-deny scope inheritance. Ported
in spirit from packages/toolgovern/test/scoping/inheritance-enforcer.test.ts.
"""

from toolgovern import ScopeDeclaration, ScopeRegistry, SpawnSubAgentParams, compute_inherited_scope, has_zero_capability


class TestComputeInheritedScope:
    def test_network_intersection_never_union(self):
        coordinator = ScopeDeclaration(network=["a.com", "b.com"])
        requested = ScopeDeclaration(network=["b.com", "c.com"])
        result = compute_inherited_scope(coordinator, requested)
        assert list(result.network) == ["b.com"]

    def test_network_false_on_either_side_yields_false(self):
        coordinator = ScopeDeclaration(network=False)
        requested = ScopeDeclaration(network=["a.com"])
        result = compute_inherited_scope(coordinator, requested)
        assert result.network is False

    def test_network_true_coordinator_yields_requested(self):
        coordinator = ScopeDeclaration(network=True)
        requested = ScopeDeclaration(network=["a.com"])
        result = compute_inherited_scope(coordinator, requested)
        assert list(result.network) == ["a.com"]

    def test_grants_exactly_the_narrower_requested_host_not_the_coordinators_broader_domain(self):
        # A sub-agent that requests a specific host under a domain the coordinator holds
        # broadly must be granted that specific host, not widened out to the coordinator's
        # whole domain -- filtering only the coordinator list (the original bug) returned
        # ["example.com"] here instead of the single host actually requested.
        coordinator = ScopeDeclaration(network=["example.com"])
        requested = ScopeDeclaration(network=["api.example.com"])
        result = compute_inherited_scope(coordinator, requested)
        assert list(result.network) == ["api.example.com"]

    def test_filesystem_intersection_keeps_only_covered_paths(self):
        coordinator = ScopeDeclaration(filesystem=["/workspace"])
        requested = ScopeDeclaration(filesystem=["/workspace/sub", "/etc"])
        result = compute_inherited_scope(coordinator, requested)
        assert list(result.filesystem) == ["/workspace/sub"]

    def test_credentials_intersection(self):
        coordinator = ScopeDeclaration(credentials=["aws"])
        requested = ScopeDeclaration(credentials=["aws", "gcp"])
        result = compute_inherited_scope(coordinator, requested)
        assert list(result.credentials) == ["aws"]

    def test_never_grants_more_than_coordinator_has(self):
        coordinator = ScopeDeclaration(filesystem=["/workspace"])
        requested = ScopeDeclaration(filesystem=["/"])
        result = compute_inherited_scope(coordinator, requested)
        assert list(result.filesystem) == []

    def test_never_grants_more_than_requested(self):
        coordinator = ScopeDeclaration(filesystem=["/", "/workspace"])
        requested = ScopeDeclaration(filesystem=["/workspace/sub"])
        result = compute_inherited_scope(coordinator, requested)
        assert list(result.filesystem) == ["/workspace/sub"]


class TestHasZeroCapability:
    def test_fully_empty_scope_is_zero_capability(self):
        assert has_zero_capability(ScopeDeclaration())

    def test_network_only_is_not_zero_capability(self):
        assert not has_zero_capability(ScopeDeclaration(network=["a.com"]))

    def test_filesystem_only_is_not_zero_capability(self):
        assert not has_zero_capability(ScopeDeclaration(filesystem=["/workspace"]))

    def test_network_true_is_not_zero_capability(self):
        assert not has_zero_capability(ScopeDeclaration(network=True))

    def test_empty_network_array_is_zero_capability_component(self):
        assert has_zero_capability(ScopeDeclaration(network=[]))


class TestScopeRegistry:
    def test_register_root_agent(self):
        registry = ScopeRegistry()
        record = registry.register_root_agent("root-1", "s1", ScopeDeclaration(filesystem=["/workspace"]))
        assert record.agent_id == "root-1"
        assert list(record.granted_scope.filesystem) == ["/workspace"]
        assert registry.has("root-1")

    def test_spawn_sub_agent_intersects_with_coordinator(self):
        registry = ScopeRegistry()
        registry.register_root_agent("coordinator", "s1", ScopeDeclaration(filesystem=["/workspace"]))
        sub = registry.spawn_sub_agent(
            SpawnSubAgentParams(
                coordinator_id="coordinator",
                sub_agent_id="sub-1",
                session_id="s1",
                requested_scope=ScopeDeclaration(filesystem=["/workspace/sub", "/etc"]),
            )
        )
        assert list(sub.granted_scope.filesystem) == ["/workspace/sub"]
        assert sub.coordinator_id == "coordinator"
        assert list(sub.requested_scope.filesystem) == ["/workspace/sub", "/etc"]

    def test_spawn_under_unregistered_coordinator_yields_empty_scope(self):
        registry = ScopeRegistry()
        sub = registry.spawn_sub_agent(
            SpawnSubAgentParams(
                coordinator_id="never-registered",
                sub_agent_id="sub-1",
                session_id="s1",
                requested_scope=ScopeDeclaration(network=True, filesystem=["/"], credentials=["all"]),
            )
        )
        assert sub.granted_scope.network is False
        assert list(sub.granted_scope.filesystem) == []
        assert list(sub.granted_scope.credentials) == []

    def test_get_effective_scope(self):
        registry = ScopeRegistry()
        registry.register_root_agent("root-1", "s1", ScopeDeclaration(filesystem=["/x"]))
        scope = registry.get_effective_scope("root-1")
        assert list(scope.filesystem) == ["/x"]
        assert registry.get_effective_scope("unknown") is None

    def test_is_zero_capability_for_registered_zero_grant(self):
        registry = ScopeRegistry()
        registry.register_root_agent("coordinator", "s1", ScopeDeclaration())
        registry.spawn_sub_agent(
            SpawnSubAgentParams(
                coordinator_id="coordinator",
                sub_agent_id="sub-1",
                session_id="s1",
                requested_scope=ScopeDeclaration(filesystem=["/anything"]),
            )
        )
        assert registry.is_zero_capability("sub-1")

    def test_is_zero_capability_false_for_unregistered_agent(self):
        registry = ScopeRegistry()
        assert not registry.is_zero_capability("never-seen")
