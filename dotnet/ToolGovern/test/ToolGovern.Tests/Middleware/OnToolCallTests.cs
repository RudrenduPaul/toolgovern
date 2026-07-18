using System.Text;
using System.Text.Json;
using ToolGovern;
using ToolGovern.Approval;
using ToolGovern.Middleware;
using ToolGovern.Scoping;
using ToolGovern.Trace;
using Xunit;
using static ToolGovern.Middleware.ToolGovernMiddleware;

namespace ToolGovern.Tests.Middleware;

public sealed class ShellResult
{
    public required string Ran { get; init; }
}

public class OnToolCallTests : IDisposable
{
    private readonly List<string> _tempDirs = [];

    private string MakeTempTraceFile()
    {
        var dir = Directory.CreateTempSubdirectory("toolgovern-middleware-").FullName;
        _tempDirs.Add(dir);
        return Path.Combine(dir, "trace.jsonl");
    }

    public void Dispose()
    {
        foreach (var dir in _tempDirs)
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }

    private static ToolDefinition<ShellResult> MakeShellTool() => new()
    {
        Name = "bash",
        Execute = args => Task.FromResult(new ShellResult { Ran = (string)args["command"]! }),
    };

    private static ScopeDeclaration WorkspaceScope(NetworkScope? network = null, IReadOnlyList<string>? credentials = null) => new()
    {
        Network = network ?? NetworkScope.False,
        Filesystem = ["./workspace"],
        Credentials = credentials ?? [],
    };

    private static async Task<List<JsonElement>> ReadTraceLines(string filePath)
    {
        var raw = await File.ReadAllTextAsync(filePath, Encoding.UTF8);
        return raw.Trim().Split('\n').Select(line => JsonDocument.Parse(line).RootElement).ToList();
    }

    [Fact]
    public async Task allows_a_clean_call_through()
    {
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions { Scope = WorkspaceScope() });
        var result = await gated.Execute(new Dictionary<string, object?> { ["command"] = "ls ./workspace" });
        Assert.Equal("ls ./workspace", result.Ran);
    }

    [Fact]
    public async Task denies_a_high_risk_call_and_never_executes_the_wrapped_tool()
    {
        var executed = false;
        var tool = new ToolDefinition<object?>
        {
            Name = "bash",
            Execute = args => { executed = true; return Task.FromResult<object?>(new ShellResult { Ran = (string)args["command"]! }); },
        };
        var gated = GovernTool(tool, new GovernToolOptions { Scope = WorkspaceScope() });

        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "rm -rf /" }));
        Assert.False(executed);
    }

    [Fact]
    public async Task denial_carries_the_fired_rule_ids()
    {
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions { Scope = WorkspaceScope() });
        var ex = await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "rm -rf /" }));
        Assert.Contains(ex.DecisionInfo.FiredRules, r => r.RuleId == "TG01-rm-rf");
    }

    [Fact]
    public async Task require_approval_executes_when_approved()
    {
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(),
            OnApprovalRequired = _ => Task.FromResult(new ApprovalOutcome { Approved = true }),
        });
        var result = await gated.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" });
        Assert.Equal("sudo apt-get update", result.Ran);
    }

    [Fact]
    public async Task require_approval_denies_when_rejected()
    {
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(),
            OnApprovalRequired = _ => Task.FromResult(new ApprovalOutcome { Approved = false }),
        });
        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" }));
    }

    [Fact]
    public async Task require_approval_fails_closed_with_no_handler()
    {
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions { Scope = WorkspaceScope() });
        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" }));
    }

    [Fact]
    public async Task require_approval_fails_closed_on_timeout()
    {
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(),
            OnApprovalRequired = _ => new TaskCompletionSource<ApprovalOutcome>().Task, // never resolves
            ApprovalTimeoutMs = 20,
        });
        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" }));
    }

    [Fact]
    public async Task require_approval_fails_closed_when_handler_throws_synchronously()
    {
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(),
            OnApprovalRequired = _ => throw new InvalidOperationException("handler blew up"),
        });
        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" }));
    }

    [Fact]
    public async Task require_approval_fails_closed_when_handler_task_faults()
    {
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(),
            OnApprovalRequired = _ => Task.FromException<ApprovalOutcome>(new InvalidOperationException("async handler blew up")),
        });
        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" }));
    }

    [Fact]
    public async Task still_writes_a_trace_entry_when_the_approval_handler_throws()
    {
        var filePath = MakeTempTraceFile();
        var trace = new TraceWriter(filePath);
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(),
            Trace = trace,
            OnApprovalRequired = _ => throw new InvalidOperationException("handler blew up"),
        });
        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" }));

        var lines = await ReadTraceLines(filePath);
        Assert.Equal("deny", lines[0].GetProperty("decision").GetString());
        Assert.Contains(lines[0].GetProperty("rule_fired").EnumerateArray().Select(e => e.GetString()), r => r == "TG01-sudo");
    }

    [Fact]
    public async Task records_final_allow_decision_after_human_approves()
    {
        var filePath = MakeTempTraceFile();
        var trace = new TraceWriter(filePath);
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(), Trace = trace,
            OnApprovalRequired = _ => Task.FromResult(new ApprovalOutcome { Approved = true }),
        });

        var result = await gated.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" });
        Assert.Equal("sudo apt-get update", result.Ran);

        var lines = await ReadTraceLines(filePath);
        Assert.Equal("allow", lines[0].GetProperty("decision").GetString());
    }

    [Fact]
    public async Task records_final_deny_decision_after_human_denies()
    {
        var filePath = MakeTempTraceFile();
        var trace = new TraceWriter(filePath);
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(), Trace = trace,
            OnApprovalRequired = _ => Task.FromResult(new ApprovalOutcome { Approved = false }),
        });

        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" }));

        var lines = await ReadTraceLines(filePath);
        Assert.Equal("deny", lines[0].GetProperty("decision").GetString());
    }

    [Fact]
    public async Task records_approved_by_on_the_trace_entry()
    {
        var filePath = MakeTempTraceFile();
        var trace = new TraceWriter(filePath);
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(), Trace = trace,
            OnApprovalRequired = _ => Task.FromResult(new ApprovalOutcome { Approved = true, ApprovedBy = "alice@example.com" }),
        });

        await gated.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" });

        var lines = await ReadTraceLines(filePath);
        Assert.Equal("alice@example.com", lines[0].GetProperty("approved_by").GetString());
    }

    [Fact]
    public async Task supports_an_async_approval_handler()
    {
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(),
            OnApprovalRequired = async _ => { await Task.Delay(5); return new ApprovalOutcome { Approved = true }; },
        });
        var result = await gated.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" });
        Assert.Equal("sudo apt-get update", result.Ran);
    }

    [Fact]
    public async Task default_decision_overrides_a_clean_call_to_deny()
    {
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions { Scope = WorkspaceScope(), DefaultDecision = Decision.Deny });
        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "ls ./workspace" }));
    }

    [Fact]
    public async Task default_decision_does_not_override_an_explicit_rule_verdict()
    {
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(), DefaultDecision = Decision.Deny,
            OnApprovalRequired = _ => Task.FromResult(new ApprovalOutcome { Approved = true }),
        });
        var result = await gated.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" });
        Assert.Equal("sudo apt-get update", result.Ran);
    }

    [Fact]
    public async Task registers_root_agent_and_grants_its_own_declared_scope()
    {
        var registry = new ScopeRegistry();
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(), AgentId = "coordinator", SessionId = "s1", ScopeRegistry = registry,
        });
        await gated.Execute(new Dictionary<string, object?> { ["command"] = "ls ./workspace" });
        Assert.Equal(WorkspaceScope(), registry.GetEffectiveScope("coordinator"));
    }

    [Fact]
    public async Task sub_agent_capped_to_intersection_with_coordinator()
    {
        var registry = new ScopeRegistry();
        registry.RegisterRootAgent("coordinator", "s1", WorkspaceScope());
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = new ScopeDeclaration { Network = NetworkScope.True, Filesystem = ["./workspace", "/"], Credentials = ["anything"] },
            AgentId = "research-sub", SessionId = "s1", CoordinatorId = "coordinator", ScopeRegistry = registry,
        });
        await gated.Execute(new Dictionary<string, object?> { ["command"] = "ls ./workspace" });
        Assert.Equal(WorkspaceScope(), registry.GetEffectiveScope("research-sub"));
    }

    [Fact]
    public async Task denies_sub_agent_call_for_credential_coordinator_never_had()
    {
        var registry = new ScopeRegistry();
        registry.RegisterRootAgent("coordinator", "s1", WorkspaceScope());
        var readTool = new ToolDefinition<object?>
        {
            Name = "fs.read",
            Execute = _ => Task.FromResult<object?>(new Dictionary<string, object?> { ["contents"] = "secret" }),
        };
        var gated = GovernTool(readTool, new GovernToolOptions
        {
            Scope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [".aws/credentials"] },
            AgentId = "research-sub", SessionId = "s1", CoordinatorId = "coordinator", ScopeRegistry = registry,
        });

        var ex = await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["path"] = ".aws/credentials" }));
        var ruleIds = ex.DecisionInfo.FiredRules.Select(r => r.RuleId).ToList();
        Assert.Contains("TG04-cloud-credential-file", ruleIds);
        Assert.Contains("TG05-credential-exceeds-grant", ruleIds);
    }

    [Fact]
    public async Task trace_writes_one_entry_per_call()
    {
        var filePath = MakeTempTraceFile();
        var trace = new TraceWriter(filePath);
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(), AgentId = "coordinator", SessionId = "s1", Trace = trace,
        });

        await gated.Execute(new Dictionary<string, object?> { ["command"] = "ls ./workspace" });
        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "rm -rf /" }));

        var lines = await ReadTraceLines(filePath);
        Assert.Equal(2, lines.Count);
        Assert.Equal("allow", lines[0].GetProperty("decision").GetString());
        Assert.Equal("deny", lines[1].GetProperty("decision").GetString());
        Assert.Contains(lines[1].GetProperty("rule_fired").EnumerateArray().Select(e => e.GetString()), r => r == "TG01-rm-rf");
        Assert.Equal(lines[0].GetProperty("trace_id").GetString(), lines[1].GetProperty("prior_trace_id").GetString());
    }

    [Fact]
    public async Task trace_records_synthetic_rule_fired_marker_for_default_decision_deny()
    {
        var filePath = MakeTempTraceFile();
        var trace = new TraceWriter(filePath);
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(), AgentId = "coordinator", SessionId = "s1", Trace = trace, DefaultDecision = Decision.Deny,
        });

        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "ls ./workspace" }));
        var lines = await ReadTraceLines(filePath);
        Assert.Equal("deny", lines[0].GetProperty("decision").GetString());
        Assert.Equal(["policy-default-decision"], lines[0].GetProperty("rule_fired").EnumerateArray().Select(e => e.GetString()));
    }

    [Fact]
    public async Task rules_disable_suppresses_a_specific_rule()
    {
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(), Rules = new RuleOverrides { Disable = ["TG01-rm-rf"] },
        });
        var result = await gated.Execute(new Dictionary<string, object?> { ["command"] = "rm -rf /" });
        Assert.Equal("rm -rf /", result.Ran);
    }

    [Fact]
    public async Task rules_require_approval_downgrades_a_deny_to_an_approval_gate()
    {
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(),
            Rules = new RuleOverrides { RequireApproval = ["TG01-rm-rf"] },
            OnApprovalRequired = _ => Task.FromResult(new ApprovalOutcome { Approved = true }),
        });
        var result = await gated.Execute(new Dictionary<string, object?> { ["command"] = "rm -rf /" });
        Assert.Equal("rm -rf /", result.Ran);
    }

    [Fact]
    public async Task on_decision_fires_for_every_call()
    {
        var seen = new List<Decision>();
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(), OnDecision = info => seen.Add(info.Decision),
        });
        await gated.Execute(new Dictionary<string, object?> { ["command"] = "ls ./workspace" });
        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "rm -rf /" }));
        Assert.Equal([Decision.Allow, Decision.Deny], seen);
    }

    private static ToolDefinition<object?> MakeThrowingTool(string message) => new()
    {
        Name = "bash",
        Execute = _ => throw new InvalidOperationException(message),
    };

    [Fact]
    public async Task catches_an_error_thrown_inside_tool_execute()
    {
        var filePath = MakeTempTraceFile();
        var trace = new TraceWriter(filePath);
        var gated = GovernTool(MakeThrowingTool("/Users/secret/leaked-path failure"), new GovernToolOptions
        {
            Scope = WorkspaceScope(), AgentId = "coordinator", SessionId = "s1", Trace = trace,
        });

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "ls ./workspace" }));
        Assert.Equal("/Users/secret/leaked-path failure", ex.Message);

        var lines = await ReadTraceLines(filePath);
        Assert.Equal("allow", lines[0].GetProperty("decision").GetString());
        Assert.Equal("bash", lines[0].GetProperty("tool").GetString());
    }

    [Fact]
    public async Task on_tool_result_redacts_a_thrown_error()
    {
        var gated = GovernTool(MakeThrowingTool("leaked secret: sk-12345"), new GovernToolOptions
        {
            Scope = WorkspaceScope(),
            OnToolResult = (result, _) => result is Exception ? new Dictionary<string, object?> { ["error"] = "redacted" } : result,
        });
        var result = await gated.Execute(new Dictionary<string, object?> { ["command"] = "ls ./workspace" });
        var dict = Assert.IsType<Dictionary<string, object?>>(result);
        Assert.Equal("redacted", dict["error"]);
    }

    [Fact]
    public async Task on_tool_result_transforms_a_successful_result()
    {
        var tool = new ToolDefinition<object?>
        {
            Name = "bash",
            Execute = args => Task.FromResult<object?>(new Dictionary<string, object?>
            {
                ["ran"] = args["command"], ["secret"] = "sk-abc123",
            }),
        };
        var gated = GovernTool(tool, new GovernToolOptions
        {
            Scope = WorkspaceScope(),
            OnToolResult = (result, _) =>
            {
                var dict = new Dictionary<string, object?>((Dictionary<string, object?>)result!) { ["secret"] = "[REDACTED]" };
                return dict;
            },
        });
        var result = await gated.Execute(new Dictionary<string, object?> { ["command"] = "ls ./workspace" });
        var resultDict = Assert.IsType<Dictionary<string, object?>>(result);
        Assert.Equal("[REDACTED]", resultDict["secret"]);
        Assert.Equal("ls ./workspace", resultDict["ran"]);
    }

    [Fact]
    public async Task on_tool_result_receives_the_rule_context()
    {
        RuleContext? seenCtx = null;
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(), AgentId = "coordinator", SessionId = "s1",
            OnToolResult = (result, ctx) => { seenCtx = ctx; return result; },
        });
        await gated.Execute(new Dictionary<string, object?> { ["command"] = "ls ./workspace" });
        Assert.NotNull(seenCtx);
        Assert.Equal("coordinator", seenCtx!.AgentId);
        Assert.Equal("s1", seenCtx.SessionId);
        Assert.Equal("bash", seenCtx.Tool);
    }

    [Fact]
    public async Task without_on_tool_result_a_successful_result_passes_through_unchanged()
    {
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions { Scope = WorkspaceScope() });
        var result = await gated.Execute(new Dictionary<string, object?> { ["command"] = "ls ./workspace" });
        Assert.Equal("ls ./workspace", result.Ran);
    }

    [Fact]
    public void agent_identity_rejects_an_empty_explicit_agent_id() =>
        Assert.Throws<InvalidAgentIdException>(() =>
            GovernTool(MakeShellTool(), new GovernToolOptions { Scope = WorkspaceScope(), AgentId = "" }));

    [Fact]
    public void agent_identity_rejects_an_agent_id_containing_a_null_byte() =>
        Assert.Throws<InvalidAgentIdException>(() =>
            GovernTool(MakeShellTool(), new GovernToolOptions { Scope = WorkspaceScope(), AgentId = "agent\0-evil" }));

    [Fact]
    public void agent_identity_rejects_an_agent_id_containing_an_embedded_newline() =>
        Assert.Throws<InvalidAgentIdException>(() =>
            GovernTool(MakeShellTool(), new GovernToolOptions { Scope = WorkspaceScope(), AgentId = "agent\nfake_trace_line" }));

    [Fact]
    public void agent_identity_rejects_an_agent_id_past_the_length_ceiling() =>
        Assert.Throws<InvalidAgentIdException>(() =>
            GovernTool(MakeShellTool(), new GovernToolOptions { Scope = WorkspaceScope(), AgentId = new string('a', 257) }));

    [Fact]
    public void agent_identity_never_executes_the_wrapped_tool_when_malformed()
    {
        var executed = false;
        var tool = new ToolDefinition<object?>
        {
            Name = "bash",
            Execute = args => { executed = true; return Task.FromResult<object?>(new ShellResult { Ran = (string)args["command"]! }); },
        };
        Assert.Throws<InvalidAgentIdException>(() =>
            GovernTool(tool, new GovernToolOptions { Scope = WorkspaceScope(), AgentId = "" }));
        Assert.False(executed);
    }

    [Fact]
    public async Task agent_identity_accepts_a_well_formed_explicit_agent_id()
    {
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions { Scope = WorkspaceScope(), AgentId = "coordinator" });
        var result = await gated.Execute(new Dictionary<string, object?> { ["command"] = "ls ./workspace" });
        Assert.Equal("ls ./workspace", result.Ran);
    }

    [Fact]
    public async Task agent_id_source_records_explicit()
    {
        var filePath = MakeTempTraceFile();
        var trace = new TraceWriter(filePath);
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions { Scope = WorkspaceScope(), AgentId = "coordinator", Trace = trace });
        await gated.Execute(new Dictionary<string, object?> { ["command"] = "ls ./workspace" });

        var lines = await ReadTraceLines(filePath);
        Assert.Equal("coordinator", lines[0].GetProperty("agent_id").GetString());
        Assert.Equal("explicit", lines[0].GetProperty("agent_id_source").GetString());
    }

    [Fact]
    public async Task agent_id_source_records_fallback()
    {
        var filePath = MakeTempTraceFile();
        var trace = new TraceWriter(filePath);
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions { Scope = WorkspaceScope(), Trace = trace });
        await gated.Execute(new Dictionary<string, object?> { ["command"] = "ls ./workspace" });

        var lines = await ReadTraceLines(filePath);
        Assert.Equal("default-agent", lines[0].GetProperty("agent_id").GetString());
        Assert.Equal("fallback", lines[0].GetProperty("agent_id_source").GetString());
    }

    [Fact]
    public async Task idempotency_returns_cached_result_for_identical_retry()
    {
        var calls = 0;
        var tool = new ToolDefinition<object?>
        {
            Name = "charge-card",
            Execute = _ => { calls += 1; return Task.FromResult<object?>(new Dictionary<string, object?> { ["chargeId"] = calls }); },
        };
        var gated = GovernTool(tool, new GovernToolOptions
        {
            Scope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [] },
            Idempotency = new IdempotencyOptions { Enabled = true, TtlMs = 5_000 },
        });

        var first = (Dictionary<string, object?>)(await gated.Execute(new Dictionary<string, object?> { ["amount"] = 100, ["to"] = "acct-1" }))!;
        var second = (Dictionary<string, object?>)(await gated.Execute(new Dictionary<string, object?> { ["amount"] = 100, ["to"] = "acct-1" }))!;

        Assert.Equal(1, first["chargeId"]);
        Assert.Equal(1, second["chargeId"]);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task idempotency_key_order_is_irrelevant()
    {
        var calls = 0;
        var tool = new ToolDefinition<object?>
        {
            Name = "charge-card",
            Execute = _ => { calls += 1; return Task.FromResult<object?>(new Dictionary<string, object?> { ["chargeId"] = calls }); },
        };
        var gated = GovernTool(tool, new GovernToolOptions
        {
            Scope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [] },
            Idempotency = new IdempotencyOptions { Enabled = true, TtlMs = 5_000 },
        });

        await gated.Execute(new Dictionary<string, object?> { ["amount"] = 100, ["to"] = "acct-1" });
        var second = (Dictionary<string, object?>)(await gated.Execute(new Dictionary<string, object?> { ["to"] = "acct-1", ["amount"] = 100 }))!;

        Assert.Equal(1, second["chargeId"]);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task idempotency_does_not_cache_across_different_arguments()
    {
        var calls = 0;
        var tool = new ToolDefinition<object?>
        {
            Name = "charge-card",
            Execute = _ => { calls += 1; return Task.FromResult<object?>(new Dictionary<string, object?> { ["chargeId"] = calls }); },
        };
        var gated = GovernTool(tool, new GovernToolOptions
        {
            Scope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [] },
            Idempotency = new IdempotencyOptions { Enabled = true, TtlMs = 5_000 },
        });

        await gated.Execute(new Dictionary<string, object?> { ["amount"] = 100, ["to"] = "acct-1" });
        await gated.Execute(new Dictionary<string, object?> { ["amount"] = 200, ["to"] = "acct-1" });
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task idempotency_executes_again_after_ttl_expires()
    {
        var calls = 0;
        var tool = new ToolDefinition<object?>
        {
            Name = "charge-card",
            Execute = _ => { calls += 1; return Task.FromResult<object?>(new Dictionary<string, object?> { ["chargeId"] = calls }); },
        };
        var gated = GovernTool(tool, new GovernToolOptions
        {
            Scope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [] },
            Idempotency = new IdempotencyOptions { Enabled = true, TtlMs = 20 },
        });

        var first = (Dictionary<string, object?>)(await gated.Execute(new Dictionary<string, object?> { ["amount"] = 100, ["to"] = "acct-1" }))!;
        await Task.Delay(80);
        var second = (Dictionary<string, object?>)(await gated.Execute(new Dictionary<string, object?> { ["amount"] = 100, ["to"] = "acct-1" }))!;

        Assert.Equal(1, first["chargeId"]);
        Assert.Equal(2, second["chargeId"]);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task idempotency_does_not_cache_a_denied_call()
    {
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(), Idempotency = new IdempotencyOptions { Enabled = true, TtlMs = 5_000 },
        });
        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "rm -rf /" }));
        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "rm -rf /" }));
    }

    [Fact]
    public async Task idempotency_not_enabled_by_default_no_regression()
    {
        var calls = 0;
        var tool = new ToolDefinition<object?>
        {
            Name = "charge-card",
            Execute = _ => { calls += 1; return Task.FromResult<object?>(new Dictionary<string, object?> { ["chargeId"] = calls }); },
        };
        var gated = GovernTool(tool, new GovernToolOptions { Scope = new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [] } });

        var first = (Dictionary<string, object?>)(await gated.Execute(new Dictionary<string, object?> { ["amount"] = 100, ["to"] = "acct-1" }))!;
        var second = (Dictionary<string, object?>)(await gated.Execute(new Dictionary<string, object?> { ["amount"] = 100, ["to"] = "acct-1" }))!;
        Assert.Equal(1, first["chargeId"]);
        Assert.Equal(2, second["chargeId"]);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task dns_resolution_check_runs_through_governTool_real_call_chain()
    {
        var executed = false;
        var tool = new ToolDefinition<object?>
        {
            Name = "http.get",
            Execute = args => { executed = true; return Task.FromResult<object?>(new Dictionary<string, object?> { ["host"] = args["host"] }); },
        };
        var gated = GovernTool(tool, new GovernToolOptions
        {
            Scope = new ScopeDeclaration { Network = NetworkScope.FromAllowlist(["other.example"]), Filesystem = [], Credentials = [] },
        });

        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["host"] = "localhost" }));
        Assert.False(executed);
    }

    [Fact]
    public async Task dns_resolution_denial_carries_the_rule_id()
    {
        var tool = new ToolDefinition<object?>
        {
            Name = "http.get",
            Execute = args => Task.FromResult<object?>(new Dictionary<string, object?> { ["host"] = args["host"] }),
        };
        var gated = GovernTool(tool, new GovernToolOptions
        {
            Scope = new ScopeDeclaration { Network = NetworkScope.FromAllowlist(["other.example"]), Filesystem = [], Credentials = [] },
        });

        var ex = await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["host"] = "localhost" }));
        Assert.Contains(ex.DecisionInfo.FiredRules, r => r.RuleId == "TG03-dns-resolves-private");
    }

    [Fact]
    public async Task a_clean_call_with_no_host_argument_is_unaffected_by_classify_async()
    {
        var result = await GovernTool(MakeShellTool(), new GovernToolOptions { Scope = WorkspaceScope() })
            .Execute(new Dictionary<string, object?> { ["command"] = "ls ./workspace" });
        Assert.Equal("ls ./workspace", result.Ran);
    }

    [Fact]
    public async Task pending_approvals_registers_before_the_synchronous_callback_runs()
    {
        var registry = new PendingApprovalRegistry();
        string? pendingIdWhenHandlerRan = null;
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(),
            PendingApprovals = registry,
            OnApprovalRequired = info =>
            {
                pendingIdWhenHandlerRan = info.PendingId;
                Assert.NotNull(info.PendingId);
                Assert.Equal(PendingApprovalStatus.Pending, registry.Get(info.PendingId!)!.Status);
                return Task.FromResult(new ApprovalOutcome { Approved = true });
            },
        });

        await gated.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" });
        Assert.NotNull(pendingIdWhenHandlerRan);
    }

    [Fact]
    public async Task pending_approvals_reflects_sync_outcome_back_into_registry()
    {
        var registry = new PendingApprovalRegistry();
        string? seenPendingId = null;
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(),
            PendingApprovals = registry,
            OnDecision = info => seenPendingId = info.PendingId,
            OnApprovalRequired = _ => Task.FromResult(new ApprovalOutcome { Approved = true, ApprovedBy = "alice@example.com" }),
        });

        await gated.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" });

        Assert.NotNull(seenPendingId);
        var entry = registry.Get(seenPendingId!);
        Assert.Equal(PendingApprovalStatus.Resolved, entry!.Status);
        Assert.Equal(Decision.Allow, entry.Resolution!.Decision);
        Assert.Equal("alice@example.com", entry.Resolution.ApprovedBy);
    }

    [Fact]
    public async Task a_genuine_sync_decision_is_terminal_later_resolve_gets_already_resolved()
    {
        var registry = new PendingApprovalRegistry();
        string? seenPendingId = null;
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(),
            PendingApprovals = registry,
            OnDecision = info => seenPendingId = info.PendingId,
            OnApprovalRequired = _ => Task.FromResult(new ApprovalOutcome { Approved = false }),
        });

        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" }));

        var outcome = await registry.ResolvePending(seenPendingId!, new ResolvePendingInput { Decision = Decision.Allow, ApprovedBy = "late-approver@example.com" });
        Assert.Equal(ResolvePendingStatus.AlreadyResolved, outcome.Status);
        Assert.Equal(Decision.Deny, outcome.FinalDecision);
    }

    [Fact]
    public async Task a_fail_closed_default_is_not_a_genuine_decision_entry_stays_pending()
    {
        var registry = new PendingApprovalRegistry();
        string? seenPendingId = null;
        var gatedNoHandler = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(), PendingApprovals = registry, OnDecision = info => seenPendingId = info.PendingId,
        });
        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gatedNoHandler.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" }));
        Assert.Equal(PendingApprovalStatus.Pending, registry.Get(seenPendingId!)!.Status);

        var registry2 = new PendingApprovalRegistry();
        string? seenPendingId2 = null;
        var gatedTimeout = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(), PendingApprovals = registry2, ApprovalTimeoutMs = 20,
            OnApprovalRequired = _ => new TaskCompletionSource<ApprovalOutcome>().Task,
            OnDecision = info => seenPendingId2 = info.PendingId,
        });
        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gatedTimeout.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" }));
        Assert.Equal(PendingApprovalStatus.Pending, registry2.Get(seenPendingId2!)!.Status);

        var registry3 = new PendingApprovalRegistry();
        string? seenPendingId3 = null;
        var gatedThrows = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(), PendingApprovals = registry3,
            OnApprovalRequired = _ => throw new InvalidOperationException("handler blew up"),
            OnDecision = info => seenPendingId3 = info.PendingId,
        });
        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gatedThrows.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" }));
        Assert.Equal(PendingApprovalStatus.Pending, registry3.Get(seenPendingId3!)!.Status);
    }

    [Fact]
    public async Task with_no_pending_approvals_registry_behavior_is_unchanged()
    {
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(), OnApprovalRequired = _ => Task.FromResult(new ApprovalOutcome { Approved = true }),
        });
        var result = await gated.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" });
        Assert.Equal("sudo apt-get update", result.Ran);
    }

    [Fact]
    public async Task an_allow_decision_does_not_register_a_pending_approval_at_all()
    {
        var registry = new PendingApprovalRegistry();
        var gated = GovernTool(MakeShellTool(), new GovernToolOptions { Scope = WorkspaceScope(), PendingApprovals = registry });
        await gated.Execute(new Dictionary<string, object?> { ["command"] = "ls ./workspace" });

        var sawPendingId = false;
        var gated2 = GovernTool(MakeShellTool(), new GovernToolOptions
        {
            Scope = WorkspaceScope(), PendingApprovals = registry, OnDecision = info => sawPendingId = info.PendingId is not null,
        });
        await gated2.Execute(new Dictionary<string, object?> { ["command"] = "ls ./workspace" });
        Assert.False(sawPendingId);
    }

    [Fact]
    public async Task resume_pending_approval_executes_the_tool_once_resolved_to_allow()
    {
        var registry = new PendingApprovalRegistry();
        string? seenPendingId = null;
        var tool = MakeShellTool();
        var gated = GovernTool(tool, new GovernToolOptions
        {
            Scope = WorkspaceScope(), PendingApprovals = registry, OnDecision = info => seenPendingId = info.PendingId,
        });
        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" }));

        var result = await ResumePendingApproval(tool, registry, seenPendingId!,
            new ResolvePendingInput { Decision = Decision.Allow, ApprovedBy = "alice@example.com" });
        Assert.Equal("sudo apt-get update", result.Ran);
    }

    [Fact]
    public async Task resume_pending_approval_populates_approved_by_end_to_end()
    {
        var filePath = MakeTempTraceFile();
        var trace = new TraceWriter(filePath);
        var registry = new PendingApprovalRegistry();
        string? seenPendingId = null;
        var tool = MakeShellTool();
        var gated = GovernTool(tool, new GovernToolOptions
        {
            Scope = WorkspaceScope(), PendingApprovals = registry, Trace = trace, AgentId = "coordinator", SessionId = "s1",
            OnDecision = info => seenPendingId = info.PendingId,
        });
        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" }));

        await ResumePendingApproval(tool, registry, seenPendingId!,
            new ResolvePendingInput { Decision = Decision.Allow, ApprovedBy = "alice@example.com" },
            new ResumePendingApprovalOptions { Trace = trace });

        var lines = await ReadTraceLines(filePath);
        Assert.Equal(2, lines.Count);
        Assert.Equal("deny", lines[0].GetProperty("decision").GetString());
        Assert.Equal("allow", lines[1].GetProperty("decision").GetString());
        Assert.Equal("alice@example.com", lines[1].GetProperty("approved_by").GetString());
        Assert.Equal(lines[0].GetProperty("trace_id").GetString(), lines[1].GetProperty("prior_trace_id").GetString());
    }

    [Fact]
    public async Task resume_pending_approval_denies_when_edited_args_reclassify_to_risky()
    {
        var registry = new PendingApprovalRegistry();
        string? seenPendingId = null;
        var executed = false;
        var tool = new ToolDefinition<object?>
        {
            Name = "bash",
            Execute = args => { executed = true; return Task.FromResult<object?>(new ShellResult { Ran = (string)args["command"]! }); },
        };
        var gated = GovernTool(tool, new GovernToolOptions
        {
            Scope = WorkspaceScope(), PendingApprovals = registry, OnDecision = info => seenPendingId = info.PendingId,
        });
        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" }));

        await Assert.ThrowsAsync<ToolGovernDenialError>(() => ResumePendingApproval(tool, registry, seenPendingId!,
            new ResolvePendingInput
            {
                Decision = Decision.Allow,
                ApprovedBy = "alice@example.com",
                EditedArgs = new Dictionary<string, object?> { ["command"] = "rm -rf /" },
            }));
        Assert.False(executed);
    }

    [Fact]
    public async Task resume_pending_approval_executes_with_edited_arguments_when_clean()
    {
        var registry = new PendingApprovalRegistry();
        string? seenPendingId = null;
        var tool = MakeShellTool();
        var gated = GovernTool(tool, new GovernToolOptions
        {
            Scope = WorkspaceScope(), PendingApprovals = registry, OnDecision = info => seenPendingId = info.PendingId,
        });
        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" }));

        var result = await ResumePendingApproval(tool, registry, seenPendingId!,
            new ResolvePendingInput { Decision = Decision.Allow, EditedArgs = new Dictionary<string, object?> { ["command"] = "ls ./workspace" } });
        Assert.Equal("ls ./workspace", result.Ran);
    }

    [Fact]
    public async Task resume_pending_approval_throws_for_unrecognized_pending_id()
    {
        var registry = new PendingApprovalRegistry();
        var executed = false;
        var tool = new ToolDefinition<object?>
        {
            Name = "bash",
            Execute = args => { executed = true; return Task.FromResult<object?>(new ShellResult { Ran = (string)args["command"]! }); },
        };
        await Assert.ThrowsAsync<PendingApprovalNotResolvableException>(() =>
            ResumePendingApproval(tool, registry, "never-registered", new ResolvePendingInput { Decision = Decision.Allow }));
        Assert.False(executed);
    }

    [Fact]
    public async Task resume_pending_approval_via_alias_still_resumes_correctly()
    {
        var registry = new PendingApprovalRegistry();
        string? seenPendingId = null;
        var tool = MakeShellTool();
        var gated = GovernTool(tool, new GovernToolOptions
        {
            Scope = WorkspaceScope(), PendingApprovals = registry, OnDecision = info => seenPendingId = info.PendingId,
        });
        await Assert.ThrowsAsync<ToolGovernDenialError>(() => gated.Execute(new Dictionary<string, object?> { ["command"] = "sudo apt-get update" }));

        registry.RegisterAlias(seenPendingId!, "webhook-thread-id-v2");
        var result = await ResumePendingApproval(tool, registry, "webhook-thread-id-v2", new ResolvePendingInput { Decision = Decision.Allow });
        Assert.Equal("sudo apt-get update", result.Ran);
    }
}
