using ToolGovern;
using ToolGovern.Approval;
using Xunit;

namespace ToolGovern.Tests.Approval;

public class PendingApprovalRegistryTests
{
    private static readonly ScopeDeclaration WorkspaceScope = new() { Network = NetworkScope.False, Filesystem = ["./workspace"], Credentials = [] };

    private static PendingApprovalDetails Details(Dictionary<string, object?>? args = null, double? ttlMs = null) => new()
    {
        AgentId = "agent-1",
        SessionId = "s1",
        Tool = "bash",
        Args = args ?? new Dictionary<string, object?> { ["command"] = "sudo apt-get update" },
        Scope = WorkspaceScope,
        FiredRules = [new RuleMatch("TG01-sudo", "TG01", Decision.RequireApproval, "escalates privileges")],
        TtlMs = ttlMs,
    };

    [Fact]
    public async Task registers_a_pending_approval_and_resolves_it_to_allow()
    {
        var registry = new PendingApprovalRegistry();
        var pendingId = registry.RegisterPending(Details());
        Assert.Equal(PendingApprovalStatus.Pending, registry.Get(pendingId)!.Status);

        var outcome = await registry.ResolvePending(pendingId, new ResolvePendingInput { Decision = Decision.Allow, ApprovedBy = "alice@example.com" });
        Assert.Equal(ResolvePendingStatus.Resolved, outcome.Status);
        Assert.Equal(Decision.Allow, outcome.FinalDecision);
        Assert.Equal(PendingApprovalStatus.Resolved, registry.Get(pendingId)!.Status);
    }

    [Fact]
    public async Task resolves_a_pending_approval_to_deny()
    {
        var registry = new PendingApprovalRegistry();
        var pendingId = registry.RegisterPending(Details());
        var outcome = await registry.ResolvePending(pendingId, new ResolvePendingInput { Decision = Decision.Deny });
        Assert.Equal(Decision.Deny, outcome.FinalDecision);
    }

    [Fact]
    public async Task a_second_resolve_of_the_same_id_returns_already_resolved()
    {
        var registry = new PendingApprovalRegistry();
        var pendingId = registry.RegisterPending(Details());
        await registry.ResolvePending(pendingId, new ResolvePendingInput { Decision = Decision.Allow });
        var second = await registry.ResolvePending(pendingId, new ResolvePendingInput { Decision = Decision.Deny });
        Assert.Equal(ResolvePendingStatus.AlreadyResolved, second.Status);
        // The FIRST resolution's outcome, never the second one's.
        Assert.Equal(Decision.Allow, second.FinalDecision);
    }

    [Fact]
    public void register_alias_throws_for_an_unrecognized_pending_id()
    {
        var registry = new PendingApprovalRegistry();
        Assert.Throws<UnknownPendingApprovalException>(() => registry.RegisterAlias("never-registered", "some-alias"));
    }

    [Fact]
    public void register_alias_throws_when_alias_already_refers_to_a_different_pending_approval()
    {
        var registry = new PendingApprovalRegistry();
        var pendingIdA = registry.RegisterPending(Details());
        var pendingIdB = registry.RegisterPending(Details());
        registry.RegisterAlias(pendingIdA, "shared-alias");
        Assert.Throws<PendingApprovalAliasConflictException>(() => registry.RegisterAlias(pendingIdB, "shared-alias"));
    }

    [Fact]
    public async Task resolves_by_an_alias_registered_after_the_original_id()
    {
        var registry = new PendingApprovalRegistry();
        var pendingId = registry.RegisterPending(Details());
        registry.RegisterAlias(pendingId, "webhook-thread-id-v2");
        var outcome = await registry.ResolvePending("webhook-thread-id-v2", new ResolvePendingInput { Decision = Decision.Allow });
        Assert.Equal(ResolvePendingStatus.Resolved, outcome.Status);
        Assert.Equal(pendingId, outcome.PendingId);
    }

    [Fact]
    public async Task resolving_by_alias_consumes_the_same_shared_entry()
    {
        var registry = new PendingApprovalRegistry();
        var pendingId = registry.RegisterPending(Details());
        registry.RegisterAlias(pendingId, "alias-1");
        await registry.ResolvePending("alias-1", new ResolvePendingInput { Decision = Decision.Allow });
        var second = await registry.ResolvePending(pendingId, new ResolvePendingInput { Decision = Decision.Deny });
        Assert.Equal(ResolvePendingStatus.AlreadyResolved, second.Status);
        Assert.Equal(Decision.Allow, second.FinalDecision);
    }

    [Fact]
    public async Task denies_edited_args_that_would_themselves_trigger_a_deny_even_after_approval()
    {
        var registry = new PendingApprovalRegistry();
        var pendingId = registry.RegisterPending(Details());
        var outcome = await registry.ResolvePending(pendingId, new ResolvePendingInput
        {
            Decision = Decision.Allow,
            ApprovedBy = "alice@example.com",
            EditedArgs = new Dictionary<string, object?> { ["command"] = "rm -rf /" },
        });
        Assert.Equal(Decision.Deny, outcome.FinalDecision);
    }

    [Fact]
    public async Task allows_edited_args_that_remain_clean_under_the_classifier()
    {
        var registry = new PendingApprovalRegistry();
        var pendingId = registry.RegisterPending(Details());
        var outcome = await registry.ResolvePending(pendingId, new ResolvePendingInput
        {
            Decision = Decision.Allow,
            EditedArgs = new Dictionary<string, object?> { ["command"] = "ls ./workspace" },
        });
        Assert.Equal(Decision.Allow, outcome.FinalDecision);
    }

    [Fact]
    public async Task a_deny_resolution_with_edited_args_does_not_trigger_reclassification()
    {
        var reclassifyCalled = false;
        var registry = new PendingApprovalRegistry(new PendingApprovalRegistryOptions
        {
            Reclassify = (ctx, options) => { reclassifyCalled = true; return ToolGovern.Classifier.ClassifierEngine.ClassifyAsync(ctx, options); },
        });
        var pendingId = registry.RegisterPending(Details());
        await registry.ResolvePending(pendingId, new ResolvePendingInput
        {
            Decision = Decision.Deny,
            EditedArgs = new Dictionary<string, object?> { ["command"] = "rm -rf /" },
        });
        Assert.False(reclassifyCalled);
    }

    [Fact]
    public async Task resolve_pending_never_creates_a_new_pending_approval_for_an_unrecognized_id()
    {
        var registry = new PendingApprovalRegistry();
        var outcome = await registry.ResolvePending("attacker-supplied-id", new ResolvePendingInput { Decision = Decision.Allow });
        Assert.Equal(ResolvePendingStatus.NotFound, outcome.Status);
        Assert.Null(registry.Get("attacker-supplied-id"));
    }

    [Fact]
    public void pending_id_is_always_server_generated()
    {
        var seenIds = new HashSet<string>();
        var registry = new PendingApprovalRegistry();
        for (var i = 0; i < 5; i++)
        {
            var id = registry.RegisterPending(Details());
            Assert.True(seenIds.Add(id), "pendingId must be unique and not caller-influenced");
        }
    }

    [Fact]
    public async Task an_expired_pending_approval_cannot_be_resolved()
    {
        var now = 1_000_000L;
        var registry = new PendingApprovalRegistry(new PendingApprovalRegistryOptions { Now = () => now });
        var pendingId = registry.RegisterPending(Details(ttlMs: 100));
        now += 200;
        var outcome = await registry.ResolvePending(pendingId, new ResolvePendingInput { Decision = Decision.Allow });
        Assert.Equal(ResolvePendingStatus.Expired, outcome.Status);
    }

    [Fact]
    public async Task with_no_ttl_ms_a_pending_approval_never_expires_on_its_own()
    {
        var now = 1_000_000L;
        var registry = new PendingApprovalRegistry(new PendingApprovalRegistryOptions { Now = () => now });
        var pendingId = registry.RegisterPending(Details());
        now += 1_000_000_000;
        var outcome = await registry.ResolvePending(pendingId, new ResolvePendingInput { Decision = Decision.Allow });
        Assert.Equal(ResolvePendingStatus.Resolved, outcome.Status);
    }

    [Fact]
    public void get_returns_null_for_an_unregistered_id()
    {
        var registry = new PendingApprovalRegistry();
        Assert.Null(registry.Get("nobody"));
    }
}
