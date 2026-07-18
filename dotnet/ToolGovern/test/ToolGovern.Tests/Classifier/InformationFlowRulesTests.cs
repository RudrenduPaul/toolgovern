using ToolGovern;
using ToolGovern.Classifier;
using Xunit;

namespace ToolGovern.Tests.Classifier;

public class InformationFlowRulesTests
{
    private static IRule Rule => InformationFlowRules.Rules.First(r => r.Id == "TG08-confidential-source-to-untrusted-sink");

    private static RuleContext Ctx(Dictionary<string, object?> args, IfcPolicy? ifc) => new()
    {
        AgentId = "agent-1",
        SessionId = "session-1",
        Tool = "forward",
        Args = args,
        Scope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [], Ifc = ifc },
    };

    [Fact]
    public void does_not_fire_when_no_ifc_policy_declared()
    {
        var ctx = Ctx(new() { ["source"] = "customers.ssn", ["sink"] = "public-api" }, null);
        Assert.Null(Rule.Evaluate(ctx));
    }

    [Fact]
    public void does_not_fire_for_a_public_source()
    {
        var ifc = new IfcPolicy
        {
            Sources = new Dictionary<string, ConfidentialityLabel> { ["public-dataset"] = ConfidentialityLabel.Public },
            SinkTrust = new Dictionary<string, ConfidentialityLabel>(),
        };
        var ctx = Ctx(new() { ["source"] = "public-dataset", ["sink"] = "anywhere" }, ifc);
        Assert.Null(Rule.Evaluate(ctx));
    }

    [Fact]
    public void requires_approval_when_sink_trust_is_undeclared()
    {
        var ifc = new IfcPolicy
        {
            Sources = new Dictionary<string, ConfidentialityLabel> { ["customers.ssn"] = ConfidentialityLabel.Confidential },
            SinkTrust = new Dictionary<string, ConfidentialityLabel>(),
        };
        var ctx = Ctx(new() { ["source"] = "customers.ssn", ["sink"] = "unknown-sink" }, ifc);
        var result = Rule.Evaluate(ctx);
        Assert.NotNull(result);
        Assert.Equal(Decision.RequireApproval, result!.Decision);
    }

    [Fact]
    public void denies_when_sink_trust_is_lower_than_source_label()
    {
        var ifc = new IfcPolicy
        {
            Sources = new Dictionary<string, ConfidentialityLabel> { ["customers.ssn"] = ConfidentialityLabel.Restricted },
            SinkTrust = new Dictionary<string, ConfidentialityLabel> { ["public-webhook"] = ConfidentialityLabel.Internal },
        };
        var ctx = Ctx(new() { ["source"] = "customers.ssn", ["sink"] = "public-webhook" }, ifc);
        var result = Rule.Evaluate(ctx);
        Assert.NotNull(result);
        Assert.Equal(Decision.Deny, result!.Decision);
    }

    [Fact]
    public void allows_when_sink_trust_meets_or_exceeds_source_label()
    {
        var ifc = new IfcPolicy
        {
            Sources = new Dictionary<string, ConfidentialityLabel> { ["customers.ssn"] = ConfidentialityLabel.Confidential },
            SinkTrust = new Dictionary<string, ConfidentialityLabel> { ["internal-audit-tool"] = ConfidentialityLabel.Restricted },
        };
        var ctx = Ctx(new() { ["source"] = "customers.ssn", ["sink"] = "internal-audit-tool" }, ifc);
        Assert.Null(Rule.Evaluate(ctx));
    }

    [Fact]
    public void matches_source_by_trailing_path_segment()
    {
        var ifc = new IfcPolicy
        {
            Sources = new Dictionary<string, ConfidentialityLabel> { ["ssn"] = ConfidentialityLabel.Restricted },
            SinkTrust = new Dictionary<string, ConfidentialityLabel> { ["public-webhook"] = ConfidentialityLabel.Public },
        };
        var ctx = Ctx(new() { ["source"] = "db/customers/ssn", ["sink"] = "public-webhook" }, ifc);
        var result = Rule.Evaluate(ctx);
        Assert.NotNull(result);
        Assert.Equal(Decision.Deny, result!.Decision);
    }

    [Fact]
    public void every_rule_belongs_to_TG08()
    {
        foreach (var r in InformationFlowRules.Rules)
        {
            Assert.Equal("TG08", r.Category);
        }
    }
}

public class ClassifierEngineTests
{
    private static RuleContext Ctx(Dictionary<string, object?> args, ScopeDeclaration? scope = null) => new()
    {
        AgentId = "agent-1",
        SessionId = "session-1",
        Tool = "bash",
        Args = args,
        Scope = scope ?? new ScopeDeclaration { Network = NetworkScope.False, Filesystem = ["./workspace"], Credentials = [] },
    };

    [Fact]
    public void allows_a_clean_call()
    {
        var result = ClassifierEngine.Classify(Ctx(new() { ["command"] = "ls ./workspace" }));
        Assert.Equal(Decision.Allow, result.Decision);
        Assert.Empty(result.FiredRules);
    }

    [Fact]
    public void denies_when_any_rule_denies_even_if_others_would_allow()
    {
        var result = ClassifierEngine.Classify(Ctx(new() { ["command"] = "rm -rf /" }));
        Assert.Equal(Decision.Deny, result.Decision);
        Assert.Contains(result.FiredRules, r => r.RuleId == "TG01-rm-rf");
    }

    [Fact]
    public void deny_outranks_require_approval_in_aggregate()
    {
        // sudo (require-approval) + rm -rf / (deny) in the same call -- aggregate must be deny.
        var result = ClassifierEngine.Classify(Ctx(new() { ["command"] = "sudo rm -rf /" }));
        Assert.Equal(Decision.Deny, result.Decision);
    }

    [Fact]
    public void disabled_rules_are_skipped_entirely()
    {
        var result = ClassifierEngine.Classify(Ctx(new() { ["command"] = "rm -rf /" }),
            new ClassifierEngine.ClassifyOptions { DisabledRules = ["TG01-rm-rf"] });
        Assert.Equal(Decision.Allow, result.Decision);
    }

    [Fact]
    public void downgrade_to_approval_softens_a_deny()
    {
        var result = ClassifierEngine.Classify(Ctx(new() { ["command"] = "rm -rf /" }),
            new ClassifierEngine.ClassifyOptions { DowngradeToApproval = ["TG01-rm-rf"] });
        Assert.Equal(Decision.RequireApproval, result.Decision);
    }

    [Fact]
    public async Task classify_async_runs_sync_rules_and_the_dns_async_rule()
    {
        var original = NetworkEgressRules.Resolver;
        try
        {
            NetworkEgressRules.Resolver = _ => Task.FromResult(new[] { System.Net.IPAddress.Parse("127.0.0.1") });
            var ctx = Ctx(new() { ["host"] = "internal-alias.attacker.io" },
                new ScopeDeclaration { Network = NetworkScope.FromAllowlist(["other.example"]), Filesystem = [], Credentials = [] });
            var result = await ClassifierEngine.ClassifyAsync(ctx);
            Assert.Equal(Decision.Deny, result.Decision);
            Assert.Contains(result.FiredRules, r => r.RuleId == "TG03-dns-resolves-private");
        }
        finally
        {
            NetworkEgressRules.Resolver = original;
        }
    }

    [Fact]
    public void classify_sync_does_not_run_the_dns_async_rule()
    {
        var ctx = Ctx(new() { ["host"] = "example.com" },
            new ScopeDeclaration { Network = NetworkScope.FromAllowlist(["other.example"]), Filesystem = [], Credentials = [] });
        var result = ClassifierEngine.Classify(ctx);
        // TG03-host-not-in-scope still fires synchronously (example.com is not in the allowlist),
        // but no DNS-resolution rule ID should ever appear from the synchronous path.
        Assert.DoesNotContain(result.FiredRules, r => r.RuleId == "TG03-dns-resolves-private");
    }
}
