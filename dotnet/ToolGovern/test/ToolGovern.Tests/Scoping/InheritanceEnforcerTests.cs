using ToolGovern;
using ToolGovern.Scoping;
using Xunit;

namespace ToolGovern.Tests.Scoping;

public class ComputeInheritedScopeTests
{
    [Fact]
    public void grants_the_intersection_of_coordinator_and_requested_filesystem_prefixes()
    {
        var granted = InheritanceEnforcer.ComputeInheritedScope(
            new ScopeDeclaration { Network = NetworkScope.False, Filesystem = ["./workspace"], Credentials = [] },
            new ScopeDeclaration { Network = NetworkScope.False, Filesystem = ["./workspace", "/etc"], Credentials = [] });
        Assert.Equal(["./workspace"], granted.Filesystem);
    }

    [Fact]
    public void never_grants_network_access_the_coordinator_does_not_have()
    {
        var granted = InheritanceEnforcer.ComputeInheritedScope(
            new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [] },
            new ScopeDeclaration { Network = NetworkScope.True, Filesystem = [], Credentials = [] });
        Assert.True(granted.Network.IsDisabled);
    }

    [Fact]
    public void grants_unrestricted_network_when_both_coordinator_and_request_are_unrestricted()
    {
        var granted = InheritanceEnforcer.ComputeInheritedScope(
            new ScopeDeclaration { Network = NetworkScope.True, Filesystem = [], Credentials = [] },
            new ScopeDeclaration { Network = NetworkScope.True, Filesystem = [], Credentials = [] });
        Assert.True(granted.Network.IsUnrestricted);
    }

    [Fact]
    public void caps_an_unrestricted_request_to_the_coordinator_allowlist()
    {
        var granted = InheritanceEnforcer.ComputeInheritedScope(
            new ScopeDeclaration { Network = NetworkScope.FromAllowlist(["example.com"]), Filesystem = [], Credentials = [] },
            new ScopeDeclaration { Network = NetworkScope.True, Filesystem = [], Credentials = [] });
        Assert.Equal(["example.com"], granted.Network.Allowlist);
    }

    [Fact]
    public void intersects_two_explicit_host_allowlists()
    {
        var granted = InheritanceEnforcer.ComputeInheritedScope(
            new ScopeDeclaration { Network = NetworkScope.FromAllowlist(["example.com", "api.example.com"]), Filesystem = [], Credentials = [] },
            new ScopeDeclaration { Network = NetworkScope.FromAllowlist(["example.com", "attacker.io"]), Filesystem = [], Credentials = [] });
        Assert.Equal(["example.com", "api.example.com"], granted.Network.Allowlist);
    }

    [Fact]
    public void drops_a_coordinator_host_that_has_no_match_anywhere_in_the_request()
    {
        var granted = InheritanceEnforcer.ComputeInheritedScope(
            new ScopeDeclaration { Network = NetworkScope.FromAllowlist(["example.com", "internal.corp"]), Filesystem = [], Credentials = [] },
            new ScopeDeclaration { Network = NetworkScope.FromAllowlist(["example.com"]), Filesystem = [], Credentials = [] });
        Assert.Equal(["example.com"], granted.Network.Allowlist);
    }

    [Fact]
    public void grants_exactly_the_narrower_requested_host()
    {
        var granted = InheritanceEnforcer.ComputeInheritedScope(
            new ScopeDeclaration { Network = NetworkScope.FromAllowlist(["example.com"]), Filesystem = [], Credentials = [] },
            new ScopeDeclaration { Network = NetworkScope.FromAllowlist(["api.example.com"]), Filesystem = [], Credentials = [] });
        Assert.Equal(["api.example.com"], granted.Network.Allowlist);
    }

    [Fact]
    public void never_grants_a_credential_the_coordinator_does_not_have()
    {
        var granted = InheritanceEnforcer.ComputeInheritedScope(
            new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [] },
            new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [".aws/credentials"] });
        Assert.Empty(granted.Credentials);
    }

    [Fact]
    public void grants_a_credential_present_in_both_coordinator_and_request()
    {
        var granted = InheritanceEnforcer.ComputeInheritedScope(
            new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [".aws/credentials"] },
            new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [".aws/credentials"] });
        Assert.Equal([".aws/credentials"], granted.Credentials);
    }

    [Fact]
    public void requesting_nothing_grants_nothing_even_with_broad_coordinator_access()
    {
        var granted = InheritanceEnforcer.ComputeInheritedScope(
            new ScopeDeclaration { Network = NetworkScope.True, Filesystem = ["./workspace", "/data"], Credentials = ["api-key"] },
            ScopeDeclarationHelpers.EmptyScope);
        Assert.Equal(ScopeDeclarationHelpers.EmptyScope, granted);
    }
}

public class ScopeRegistryTests
{
    [Fact]
    public void registers_a_root_agent_with_its_own_declared_scope()
    {
        var registry = new ScopeRegistry();
        var record = registry.RegisterRootAgent("coordinator", "s1",
            new ScopeDeclaration { Network = NetworkScope.FromAllowlist(["example.com"]), Filesystem = ["./workspace"], Credentials = [] });
        Assert.Equal(["example.com"], record.GrantedScope.Network.Allowlist);
        Assert.True(registry.Has("coordinator"));
    }

    [Fact]
    public void a_sub_agent_never_exceeds_its_coordinator_granted_scope()
    {
        var registry = new ScopeRegistry();
        registry.RegisterRootAgent("coordinator", "s1", new ScopeDeclaration { Network = NetworkScope.False, Filesystem = ["./workspace"], Credentials = [] });

        var subRecord = registry.SpawnSubAgent(new SpawnSubAgentParams
        {
            CoordinatorId = "coordinator",
            SubAgentId = "research-sub",
            SessionId = "s1",
            RequestedScope = new ScopeDeclaration { Network = NetworkScope.True, Filesystem = ["./workspace", "/etc"], Credentials = [".aws/credentials"] },
        });

        Assert.True(subRecord.GrantedScope.Network.IsDisabled);
        Assert.Equal(["./workspace"], subRecord.GrantedScope.Filesystem);
        Assert.Empty(subRecord.GrantedScope.Credentials);
    }

    [Fact]
    public void an_unregistered_coordinator_yields_the_empty_scope_for_its_sub_agent()
    {
        var registry = new ScopeRegistry();
        var subRecord = registry.SpawnSubAgent(new SpawnSubAgentParams
        {
            CoordinatorId = "never-registered",
            SubAgentId = "sub",
            SessionId = "s1",
            RequestedScope = new ScopeDeclaration { Network = NetworkScope.True, Filesystem = ["/"], Credentials = ["anything"] },
        });
        Assert.Equal(ScopeDeclarationHelpers.EmptyScope, subRecord.GrantedScope);
    }

    [Fact]
    public void a_grandchild_sub_agent_cannot_exceed_its_parent_which_cannot_exceed_the_root()
    {
        var registry = new ScopeRegistry();
        registry.RegisterRootAgent("root", "s1", new ScopeDeclaration { Network = NetworkScope.FromAllowlist(["example.com"]), Filesystem = ["./workspace"], Credentials = [] });
        registry.SpawnSubAgent(new SpawnSubAgentParams
        {
            CoordinatorId = "root",
            SubAgentId = "mid",
            SessionId = "s1",
            RequestedScope = new ScopeDeclaration { Network = NetworkScope.FromAllowlist(["example.com"]), Filesystem = ["./workspace/sub"], Credentials = [] },
        });
        var grandchild = registry.SpawnSubAgent(new SpawnSubAgentParams
        {
            CoordinatorId = "mid",
            SubAgentId = "leaf",
            SessionId = "s1",
            RequestedScope = new ScopeDeclaration { Network = NetworkScope.True, Filesystem = ["./workspace", "/"], Credentials = [] },
        });
        Assert.Empty(grandchild.GrantedScope.Filesystem);
        Assert.Equal(["example.com"], grandchild.GrantedScope.Network.Allowlist);
    }

    [Fact]
    public void get_effective_scope_returns_null_for_an_unknown_agent()
    {
        var registry = new ScopeRegistry();
        Assert.Null(registry.GetEffectiveScope("nobody"));
        Assert.Null(registry.GetRecord("nobody"));
        Assert.False(registry.Has("nobody"));
    }

    [Fact]
    public void is_zero_capability_true_for_a_sub_agent_whose_coordinator_had_nothing_to_grant()
    {
        var registry = new ScopeRegistry();
        registry.RegisterRootAgent("coordinator", "s1", ScopeDeclarationHelpers.EmptyScope);
        registry.SpawnSubAgent(new SpawnSubAgentParams
        {
            CoordinatorId = "coordinator",
            SubAgentId = "no-tools-sub",
            SessionId = "s1",
            RequestedScope = new ScopeDeclaration { Network = NetworkScope.True, Filesystem = ["/"], Credentials = ["anything"] },
        });
        Assert.True(registry.IsZeroCapability("no-tools-sub"));
    }

    [Fact]
    public void is_zero_capability_false_once_coordinator_grants_even_one_capability()
    {
        var registry = new ScopeRegistry();
        registry.RegisterRootAgent("coordinator", "s1", new ScopeDeclaration { Network = NetworkScope.False, Filesystem = ["./workspace"], Credentials = [] });
        registry.SpawnSubAgent(new SpawnSubAgentParams
        {
            CoordinatorId = "coordinator",
            SubAgentId = "scoped-sub",
            SessionId = "s1",
            RequestedScope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = ["./workspace"], Credentials = [] },
        });
        Assert.False(registry.IsZeroCapability("scoped-sub"));
    }

    [Fact]
    public void is_zero_capability_false_for_an_unregistered_agent()
    {
        var registry = new ScopeRegistry();
        Assert.False(registry.IsZeroCapability("nobody"));
    }
}

public class HasZeroCapabilityTests
{
    [Fact]
    public void true_for_the_empty_scope() => Assert.True(InheritanceEnforcer.HasZeroCapability(ScopeDeclarationHelpers.EmptyScope));

    [Fact]
    public void false_when_network_unrestricted_even_with_no_filesystem_credentials() =>
        Assert.False(InheritanceEnforcer.HasZeroCapability(new ScopeDeclaration { Network = NetworkScope.True, Filesystem = [], Credentials = [] }));

    [Fact]
    public void false_when_network_is_a_non_empty_allowlist() =>
        Assert.False(InheritanceEnforcer.HasZeroCapability(new ScopeDeclaration { Network = NetworkScope.FromAllowlist(["example.com"]), Filesystem = [], Credentials = [] }));

    [Fact]
    public void false_when_at_least_one_filesystem_prefix_is_granted() =>
        Assert.False(InheritanceEnforcer.HasZeroCapability(new ScopeDeclaration { Network = NetworkScope.False, Filesystem = ["./workspace"], Credentials = [] }));

    [Fact]
    public void false_when_at_least_one_credential_is_granted() =>
        Assert.False(InheritanceEnforcer.HasZeroCapability(new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [".aws/credentials"] }));

    [Fact]
    public void true_for_an_empty_network_allowlist_plus_no_filesystem_credentials() =>
        Assert.True(InheritanceEnforcer.HasZeroCapability(new ScopeDeclaration { Network = NetworkScope.FromAllowlist([]), Filesystem = [], Credentials = [] }));
}

public class ScopeDeclarationHelpersTests
{
    [Theory]
    [InlineData("", false)]
    [InlineData("agent\0-evil", false)]
    [InlineData("agent\nfake_trace_line", false)]
    [InlineData("coordinator", true)]
    public void is_valid_agent_id(string value, bool expected) =>
        Assert.Equal(expected, ScopeDeclarationHelpers.IsValidAgentId(value));

    [Fact]
    public void rejects_an_agent_id_past_the_length_ceiling() =>
        Assert.False(ScopeDeclarationHelpers.IsValidAgentId(new string('a', 257)));

    [Fact]
    public void accepts_an_agent_id_at_the_length_ceiling() =>
        Assert.True(ScopeDeclarationHelpers.IsValidAgentId(new string('a', 256)));
}
