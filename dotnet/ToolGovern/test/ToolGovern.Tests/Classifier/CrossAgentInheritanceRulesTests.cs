using ToolGovern;
using ToolGovern.Classifier;
using ToolGovern.Scoping;
using Xunit;

namespace ToolGovern.Tests.Classifier;

public class CrossAgentInheritanceRulesTests
{
    private static IRule Rule(string id) => CrossAgentInheritanceRules.Rules.First(r => r.Id == id);

    [Fact]
    public void unregistered_sub_agent_flags_a_call_with_no_registry_record()
    {
        var registry = new ScopeRegistry();
        var ctx = new RuleContext
        {
            AgentId = "ghost-sub",
            SessionId = "s1",
            CoordinatorId = "coordinator",
            Tool = "bash",
            Args = new Dictionary<string, object?> { ["command"] = "ls" },
            Scope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [] },
            ScopeRegistry = registry,
        };
        Assert.NotNull(Rule("TG05-unregistered-sub-agent").Evaluate(ctx));
    }

    [Fact]
    public void unregistered_sub_agent_does_not_flag_a_registered_sub_agent()
    {
        var registry = new ScopeRegistry();
        registry.RegisterRootAgent("coordinator", "s1", new ScopeDeclaration { Network = NetworkScope.FromAllowlist(["example.com"]), Filesystem = ["./workspace"], Credentials = [] });
        registry.SpawnSubAgent(new SpawnSubAgentParams
        {
            CoordinatorId = "coordinator",
            SubAgentId = "research-sub",
            SessionId = "s1",
            RequestedScope = new ScopeDeclaration { Network = NetworkScope.FromAllowlist(["example.com"]), Filesystem = ["./workspace"], Credentials = [] },
        });
        var ctx = new RuleContext
        {
            AgentId = "research-sub",
            SessionId = "s1",
            CoordinatorId = "coordinator",
            Tool = "bash",
            Args = new Dictionary<string, object?> { ["command"] = "ls" },
            Scope = new ScopeDeclaration { Network = NetworkScope.FromAllowlist(["example.com"]), Filesystem = ["./workspace"], Credentials = [] },
            ScopeRegistry = registry,
        };
        Assert.Null(Rule("TG05-unregistered-sub-agent").Evaluate(ctx));
    }

    [Fact]
    public void unregistered_sub_agent_does_not_flag_a_root_agent_with_no_coordinator()
    {
        var registry = new ScopeRegistry();
        var ctx = new RuleContext
        {
            AgentId = "coordinator",
            SessionId = "s1",
            Tool = "bash",
            Args = new Dictionary<string, object?> { ["command"] = "ls" },
            Scope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [] },
            ScopeRegistry = registry,
        };
        Assert.Null(Rule("TG05-unregistered-sub-agent").Evaluate(ctx));
    }

    [Fact]
    public void zero_capability_denies_any_call_from_a_zero_capability_sub_agent()
    {
        var registry = new ScopeRegistry();
        registry.RegisterRootAgent("coordinator", "s1", new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [] });
        registry.SpawnSubAgent(new SpawnSubAgentParams
        {
            CoordinatorId = "coordinator",
            SubAgentId = "no-tools-sub",
            SessionId = "s1",
            RequestedScope = new ScopeDeclaration { Network = NetworkScope.True, Filesystem = ["/"], Credentials = ["anything"] },
        });
        var grantedScope = registry.GetEffectiveScope("no-tools-sub")!;
        Assert.Equal(NetworkScope.False, grantedScope.Network);
        Assert.Empty(grantedScope.Filesystem);
        Assert.Empty(grantedScope.Credentials);

        var ctx = new RuleContext
        {
            AgentId = "no-tools-sub",
            SessionId = "s1",
            CoordinatorId = "coordinator",
            Tool = "run_query",
            Args = new Dictionary<string, object?> { ["query"] = "SELECT 1" },
            Scope = grantedScope,
            ScopeRegistry = registry,
        };
        var result = Rule("TG05-zero-capability-sub-agent").Evaluate(ctx);
        Assert.NotNull(result);
        Assert.Equal(Decision.Deny, result!.Decision);
    }

    [Fact]
    public void zero_capability_also_denies_a_recognizable_tool_call()
    {
        var registry = new ScopeRegistry();
        registry.RegisterRootAgent("coordinator", "s1", new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [] });
        registry.SpawnSubAgent(new SpawnSubAgentParams
        {
            CoordinatorId = "coordinator",
            SubAgentId = "no-tools-sub",
            SessionId = "s1",
            RequestedScope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = ["/tmp"], Credentials = [] },
        });
        var grantedScope = registry.GetEffectiveScope("no-tools-sub")!;
        var ctx = new RuleContext
        {
            AgentId = "no-tools-sub",
            SessionId = "s1",
            CoordinatorId = "coordinator",
            Tool = "fs.read",
            Args = new Dictionary<string, object?> { ["path"] = "/tmp/anything.txt", ["operation"] = "read" },
            Scope = grantedScope,
            ScopeRegistry = registry,
        };
        Assert.NotNull(Rule("TG05-zero-capability-sub-agent").Evaluate(ctx));
    }

    [Fact]
    public void zero_capability_does_not_flag_a_sub_agent_granted_at_least_one_capability()
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
        var grantedScope = registry.GetEffectiveScope("scoped-sub")!;
        var ctx = new RuleContext
        {
            AgentId = "scoped-sub",
            SessionId = "s1",
            CoordinatorId = "coordinator",
            Tool = "run_query",
            Args = new Dictionary<string, object?> { ["query"] = "SELECT 1" },
            Scope = grantedScope,
            ScopeRegistry = registry,
        };
        Assert.Null(Rule("TG05-zero-capability-sub-agent").Evaluate(ctx));
    }

    [Fact]
    public void zero_capability_does_not_flag_a_root_agent_with_empty_scope()
    {
        var registry = new ScopeRegistry();
        registry.RegisterRootAgent("lone-root", "s1", new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [] });
        var ctx = new RuleContext
        {
            AgentId = "lone-root",
            SessionId = "s1",
            Tool = "run_query",
            Args = new Dictionary<string, object?> { ["query"] = "SELECT 1" },
            Scope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [] },
            ScopeRegistry = registry,
        };
        Assert.Null(Rule("TG05-zero-capability-sub-agent").Evaluate(ctx));
    }

    [Fact]
    public void zero_capability_does_not_flag_when_no_registry_record_at_all()
    {
        var ctx = new RuleContext
        {
            AgentId = "ghost-sub",
            SessionId = "s1",
            CoordinatorId = "coordinator",
            Tool = "run_query",
            Args = new Dictionary<string, object?> { ["query"] = "SELECT 1" },
            Scope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [] },
            ScopeRegistry = new ScopeRegistry(),
        };
        Assert.Null(Rule("TG05-zero-capability-sub-agent").Evaluate(ctx));
    }

    private static ScopeRegistry BuildEscalationRegistry()
    {
        var registry = new ScopeRegistry();
        registry.RegisterRootAgent("coordinator", "s1", new ScopeDeclaration { Network = NetworkScope.False, Filesystem = ["./workspace"], Credentials = [] });
        registry.SpawnSubAgent(new SpawnSubAgentParams
        {
            CoordinatorId = "coordinator",
            SubAgentId = "research-sub",
            SessionId = "s1",
            RequestedScope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = ["./workspace"], Credentials = [".aws/credentials"] },
        });
        return registry;
    }

    [Fact]
    public void credential_exceeds_grant_flags_a_credential_requested_but_never_granted()
    {
        var registry = BuildEscalationRegistry();
        var grantedScope = registry.GetEffectiveScope("research-sub")!;
        var ctx = new RuleContext
        {
            AgentId = "research-sub",
            SessionId = "s1",
            CoordinatorId = "coordinator",
            Tool = "fs.read",
            Args = new Dictionary<string, object?> { ["path"] = ".aws/credentials" },
            Scope = grantedScope,
            ScopeRegistry = registry,
        };
        Assert.NotNull(Rule("TG05-credential-exceeds-grant").Evaluate(ctx));
    }

    [Fact]
    public void credential_exceeds_grant_does_not_flag_a_credential_both_requested_and_granted()
    {
        var registry = new ScopeRegistry();
        registry.RegisterRootAgent("coordinator", "s1", new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [".aws/credentials"] });
        registry.SpawnSubAgent(new SpawnSubAgentParams
        {
            CoordinatorId = "coordinator",
            SubAgentId = "export-sub",
            SessionId = "s1",
            RequestedScope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [".aws/credentials"] },
        });
        var grantedScope = registry.GetEffectiveScope("export-sub")!;
        var ctx = new RuleContext
        {
            AgentId = "export-sub",
            SessionId = "s1",
            CoordinatorId = "coordinator",
            Tool = "fs.read",
            Args = new Dictionary<string, object?> { ["path"] = ".aws/credentials" },
            Scope = grantedScope,
            ScopeRegistry = registry,
        };
        Assert.Null(Rule("TG05-credential-exceeds-grant").Evaluate(ctx));
    }

    [Fact]
    public void credential_exceeds_grant_does_not_flag_when_no_registry_record_at_all()
    {
        var ctx = new RuleContext
        {
            AgentId = "lone-agent",
            SessionId = "s1",
            Tool = "fs.read",
            Args = new Dictionary<string, object?> { ["path"] = ".aws/credentials" },
            Scope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [] },
        };
        Assert.Null(Rule("TG05-credential-exceeds-grant").Evaluate(ctx));
    }

    [Fact]
    public void network_exceeds_grant_flags_a_host_requested_but_never_granted()
    {
        var registry = new ScopeRegistry();
        registry.RegisterRootAgent("coordinator", "s1", new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [] });
        registry.SpawnSubAgent(new SpawnSubAgentParams
        {
            CoordinatorId = "coordinator",
            SubAgentId = "research-sub",
            SessionId = "s1",
            RequestedScope = new ScopeDeclaration { Network = NetworkScope.FromAllowlist(["attacker.io"]), Filesystem = [], Credentials = [] },
        });
        var grantedScope = registry.GetEffectiveScope("research-sub")!;
        var ctx = new RuleContext
        {
            AgentId = "research-sub",
            SessionId = "s1",
            CoordinatorId = "coordinator",
            Tool = "http.get",
            Args = new Dictionary<string, object?> { ["host"] = "attacker.io" },
            Scope = grantedScope,
            ScopeRegistry = registry,
        };
        Assert.NotNull(Rule("TG05-network-exceeds-grant").Evaluate(ctx));
    }

    [Fact]
    public void network_exceeds_grant_does_not_flag_a_host_both_requested_and_granted()
    {
        var registry = new ScopeRegistry();
        registry.RegisterRootAgent("coordinator", "s1", new ScopeDeclaration { Network = NetworkScope.FromAllowlist(["example.com"]), Filesystem = [], Credentials = [] });
        registry.SpawnSubAgent(new SpawnSubAgentParams
        {
            CoordinatorId = "coordinator",
            SubAgentId = "research-sub",
            SessionId = "s1",
            RequestedScope = new ScopeDeclaration { Network = NetworkScope.FromAllowlist(["example.com"]), Filesystem = [], Credentials = [] },
        });
        var grantedScope = registry.GetEffectiveScope("research-sub")!;
        var ctx = new RuleContext
        {
            AgentId = "research-sub",
            SessionId = "s1",
            CoordinatorId = "coordinator",
            Tool = "http.get",
            Args = new Dictionary<string, object?> { ["host"] = "example.com" },
            Scope = grantedScope,
            ScopeRegistry = registry,
        };
        Assert.Null(Rule("TG05-network-exceeds-grant").Evaluate(ctx));
    }

    [Fact]
    public void filesystem_exceeds_grant_flags_a_path_requested_but_never_granted()
    {
        var registry = new ScopeRegistry();
        registry.RegisterRootAgent("coordinator", "s1", new ScopeDeclaration { Network = NetworkScope.False, Filesystem = ["./workspace"], Credentials = [] });
        registry.SpawnSubAgent(new SpawnSubAgentParams
        {
            CoordinatorId = "coordinator",
            SubAgentId = "export-sub",
            SessionId = "s1",
            RequestedScope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = ["./workspace", "/tmp"], Credentials = [] },
        });
        var grantedScope = registry.GetEffectiveScope("export-sub")!;
        var ctx = new RuleContext
        {
            AgentId = "export-sub",
            SessionId = "s1",
            CoordinatorId = "coordinator",
            Tool = "fs.write",
            Args = new Dictionary<string, object?> { ["path"] = "/tmp/export.csv", ["operation"] = "write" },
            Scope = grantedScope,
            ScopeRegistry = registry,
        };
        Assert.NotNull(Rule("TG05-filesystem-exceeds-grant").Evaluate(ctx));
    }

    [Fact]
    public void filesystem_exceeds_grant_does_not_flag_a_path_within_what_was_granted()
    {
        var registry = new ScopeRegistry();
        registry.RegisterRootAgent("coordinator", "s1", new ScopeDeclaration { Network = NetworkScope.False, Filesystem = ["./workspace"], Credentials = [] });
        registry.SpawnSubAgent(new SpawnSubAgentParams
        {
            CoordinatorId = "coordinator",
            SubAgentId = "export-sub",
            SessionId = "s1",
            RequestedScope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = ["./workspace"], Credentials = [] },
        });
        var grantedScope = registry.GetEffectiveScope("export-sub")!;
        var ctx = new RuleContext
        {
            AgentId = "export-sub",
            SessionId = "s1",
            CoordinatorId = "coordinator",
            Tool = "fs.write",
            Args = new Dictionary<string, object?> { ["path"] = "./workspace/out.csv", ["operation"] = "write" },
            Scope = grantedScope,
            ScopeRegistry = registry,
        };
        Assert.Null(Rule("TG05-filesystem-exceeds-grant").Evaluate(ctx));
    }

    [Fact]
    public void coordinator_scope_shrunk_flags_once_coordinator_no_longer_covers_credential()
    {
        var registry = new ScopeRegistry();
        registry.RegisterRootAgent("coordinator", "s1", new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [".aws/credentials"] });
        registry.SpawnSubAgent(new SpawnSubAgentParams
        {
            CoordinatorId = "coordinator",
            SubAgentId = "export-sub",
            SessionId = "s1",
            RequestedScope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [".aws/credentials"] },
        });
        registry.RegisterRootAgent("coordinator", "s1", new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [] });

        var grantedScope = registry.GetEffectiveScope("export-sub")!;
        var ctx = new RuleContext
        {
            AgentId = "export-sub",
            SessionId = "s1",
            CoordinatorId = "coordinator",
            Tool = "fs.read",
            Args = new Dictionary<string, object?> { ["path"] = ".aws/credentials" },
            Scope = grantedScope,
            ScopeRegistry = registry,
        };
        Assert.NotNull(Rule("TG05-coordinator-scope-shrunk").Evaluate(ctx));
    }

    [Fact]
    public void coordinator_scope_shrunk_does_not_flag_when_coordinator_scope_unchanged()
    {
        var registry = new ScopeRegistry();
        registry.RegisterRootAgent("coordinator", "s1", new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [".aws/credentials"] });
        registry.SpawnSubAgent(new SpawnSubAgentParams
        {
            CoordinatorId = "coordinator",
            SubAgentId = "export-sub",
            SessionId = "s1",
            RequestedScope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [".aws/credentials"] },
        });
        var grantedScope = registry.GetEffectiveScope("export-sub")!;
        var ctx = new RuleContext
        {
            AgentId = "export-sub",
            SessionId = "s1",
            CoordinatorId = "coordinator",
            Tool = "fs.read",
            Args = new Dictionary<string, object?> { ["path"] = ".aws/credentials" },
            Scope = grantedScope,
            ScopeRegistry = registry,
        };
        Assert.Null(Rule("TG05-coordinator-scope-shrunk").Evaluate(ctx));
    }

    [Fact]
    public void every_rule_has_a_unique_id_and_belongs_to_TG05()
    {
        var ids = CrossAgentInheritanceRules.Rules.Select(r => r.Id).ToHashSet();
        Assert.Equal(CrossAgentInheritanceRules.Rules.Count, ids.Count);
        foreach (var r in CrossAgentInheritanceRules.Rules)
        {
            Assert.Equal("TG05", r.Category);
        }
    }
}
