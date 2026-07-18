using System.Text.Json;
using Microsoft.Extensions.AI;
using ToolGovern;
using ToolGovern.AgentFramework;
using ToolGovern.Middleware;
using Xunit;

namespace ToolGovern.AgentFramework.Tests;

public class ToolGovernAIFunctionTests
{
    private static ScopeDeclaration ScopeWithFilesystem(params string[] prefixes) => new()
    {
        Network = NetworkScope.False,
        Filesystem = prefixes,
        Credentials = [],
    };

    private static GovernToolOptions OptionsFor(ScopeDeclaration scope) => new()
    {
        Scope = scope,
        AgentId = "test-agent",
    };

    /// <summary>
    /// AIFunctionFactory-created AIFunctions JSON-serialize their return value -- InvokeAsync()
    /// hands back a <see cref="JsonElement"/>, not the raw CLR value the underlying method
    /// returned. This mirrors how any real caller of <see cref="AIFunction.InvokeAsync"/> reads a
    /// string-valued result back.
    /// </summary>
    private static string AsString(object? result) => result switch
    {
        JsonElement element => element.GetString() ?? element.ToString(),
        string s => s,
        _ => result?.ToString() ?? "",
    };

    [Fact]
    public async Task AllowedCall_InvokesInnerFunctionAndReturnsItsResult()
    {
        var invocationCount = 0;

        string ReadFile(string path)
        {
            invocationCount++;
            return $"contents-of:{path}";
        }

        AIFunction inner = AIFunctionFactory.Create(ReadFile, "read_file", "Reads a file from the workspace.");
        AIFunction governed = inner.WithToolGovern(OptionsFor(ScopeWithFilesystem("/workspace")));

        var result = await governed.InvokeAsync(new AIFunctionArguments
        {
            ["path"] = "/workspace/notes.txt",
        });

        Assert.Equal(1, invocationCount);
        Assert.Equal("contents-of:/workspace/notes.txt", AsString(result));
    }

    [Fact]
    public async Task DeniedCall_NeverInvokesInnerFunction()
    {
        var invocationCount = 0;

        string DeleteFile(string path, string operation)
        {
            invocationCount++;
            return $"deleted:{path}";
        }

        AIFunction inner = AIFunctionFactory.Create(DeleteFile, "delete_file", "Deletes a file.");
        AIFunction governed = inner.WithToolGovern(OptionsFor(ScopeWithFilesystem("/workspace")));

        // TG02-delete-outside-scope: a delete targeting a path outside the declared filesystem
        // scope is a real Deny verdict from ToolGovern.Net's own classifier, not a stubbed result.
        var error = await Assert.ThrowsAsync<ToolGovernDenialError>(async () =>
            await governed.InvokeAsync(new AIFunctionArguments
            {
                ["path"] = "/etc/passwd",
                ["operation"] = "delete",
            }));

        Assert.Equal(0, invocationCount);
        Assert.Equal(Decision.Deny, error.DecisionInfo.Decision);
        Assert.Contains("TG02-delete-outside-scope", error.DecisionInfo.FiredRules.Select(r => r.RuleId));
    }

    [Fact]
    public async Task AllowedCall_WithinScope_DeleteSucceeds()
    {
        var invocationCount = 0;

        string DeleteFile(string path, string operation)
        {
            invocationCount++;
            return $"deleted:{path}";
        }

        AIFunction inner = AIFunctionFactory.Create(DeleteFile, "delete_file", "Deletes a file.");
        AIFunction governed = inner.WithToolGovern(OptionsFor(ScopeWithFilesystem("/workspace")));

        var result = await governed.InvokeAsync(new AIFunctionArguments
        {
            ["path"] = "/workspace/scratch.txt",
            ["operation"] = "delete",
        });

        Assert.Equal(1, invocationCount);
        Assert.Equal("deleted:/workspace/scratch.txt", AsString(result));
    }

    [Fact]
    public async Task RequireApproval_WithNoHandler_FailsClosed()
    {
        // A write outside the declared scope is TG02-write-outside-scope, which resolves to
        // RequireApproval. With no OnApprovalRequired handler wired up, GovernTool()'s own
        // documented default is fail-closed: the call is denied, never silently allowed.
        var invocationCount = 0;

        string WriteFile(string path, string operation)
        {
            invocationCount++;
            return "ok";
        }

        AIFunction inner = AIFunctionFactory.Create(WriteFile, "write_file", "Writes a file.");
        AIFunction governed = inner.WithToolGovern(OptionsFor(ScopeWithFilesystem("/workspace")));

        var error = await Assert.ThrowsAsync<ToolGovernDenialError>(async () =>
            await governed.InvokeAsync(new AIFunctionArguments
            {
                ["path"] = "/tmp/outside.txt",
                ["operation"] = "write",
            }));

        Assert.Equal(0, invocationCount);
        // ToolGovern.Net's own GateDecisionInfo carries the classifier's PRE-approval verdict
        // (RequireApproval) even when the call is ultimately thrown as denied because no
        // OnApprovalRequired handler resolved it -- ToolGovernDenialError is still thrown (the
        // call fails closed, exactly as documented), just with the original decision label
        // preserved on DecisionInfo. This is core ToolGovern.Net behavior, unchanged by this
        // adapter, not something this test invented.
        Assert.Equal(Decision.RequireApproval, error.DecisionInfo.Decision);
        Assert.Contains("TG02-write-outside-scope", error.DecisionInfo.FiredRules.Select(r => r.RuleId));
    }

    [Fact]
    public void WrappedFunction_IsADelegatingAIFunctionOverTheOriginal()
    {
        string Noop() => "noop";
        AIFunction inner = AIFunctionFactory.Create(Noop, "noop", "Does nothing.");
        AIFunction governed = inner.WithToolGovern(OptionsFor(ScopeWithFilesystem()));

        Assert.IsType<ToolGovernAIFunction>(governed);
        // Name/description/schema pass through unchanged, exactly like any other
        // DelegatingAIFunction (e.g. Microsoft.Extensions.AI.ApprovalRequiredAIFunction) -- this
        // wrapper does not change what the model sees about the tool, only what happens before
        // the tool's real body runs.
        Assert.Equal(inner.Name, governed.Name);
        Assert.Equal(inner.Description, governed.Description);
    }
}
