# ToolGovern.AgentFramework

Route [Microsoft Agent Framework](https://github.com/microsoft/agent-framework) (.NET,
`Microsoft.Agents.AI`) `AIFunction` tool calls through
[ToolGovern.Net](https://github.com/RudrenduPaul/toolgovern)'s classifier before they execute.

```bash
dotnet add package ToolGovern.AgentFramework
```

## What this is

`.NET: Feature Request: Built-in Security & Validation Middleware for AI Function Tools`
([agent-framework#2254](https://github.com/microsoft/agent-framework/issues/2254)) asked for
exactly this: a way to intercept, validate, or reject an `AIFunction` tool call's arguments before
the real tool body runs. The framework's own maintainer (@stephentoub) answered that this is
already possible today via `DelegatingAIFunction`:

```csharp
class ValidateQueryFunction(AIFunction innerFunction) : DelegatingAIFunction(innerFunction)
{
    protected override ValueTask<object?> InvokeCoreAsync(AIFunctionArguments arguments, CancellationToken cancellationToken)
    {
        // ... validation work here ...
        return base.InvokeCoreAsync(arguments, cancellationToken);
    }
}
```

`ToolGovernAIFunction` is that exact pattern, wired to ToolGovern.Net's real multi-rule classifier
(shell-risk, filesystem-scope, network-egress, credential-access, cross-agent-inheritance,
information-flow) instead of a hand-rolled validator.

## Quick example

```csharp
using Microsoft.Extensions.AI;
using ToolGovern;
using ToolGovern.AgentFramework;
using ToolGovern.Middleware;

string ReadFile(string path) => File.ReadAllText(path);

AIFunction tool = AIFunctionFactory.Create(ReadFile, "read_file", "Reads a file from the workspace.");

AIFunction governed = tool.WithToolGovern(new GovernToolOptions
{
    Scope = new ScopeDeclaration
    {
        Network = NetworkScope.False,
        Filesystem = ["/workspace"],
        Credentials = [],
    },
    AgentId = "research-agent",
});

// Inside the declared scope -- executes for real.
var ok = await governed.InvokeAsync(new AIFunctionArguments { ["path"] = "/workspace/notes.txt" });

// Outside the declared scope -- ToolGovernDenialError, ReadFile() never runs.
try
{
    await governed.InvokeAsync(new AIFunctionArguments { ["path"] = "/etc/passwd" });
}
catch (ToolGovernDenialError error)
{
    Console.WriteLine($"blocked: {error.Message}");
}
```

Register `governed` with a `ChatClientAgent` (or any `Microsoft.Agents.AI` agent) exactly as you
would the original `tool` -- name, description, and JSON schema all pass through unchanged; only
what happens before the tool body runs is different.

## Why a per-call gate on top of `ApprovalRequiredAIFunction`?

`Microsoft.Extensions.AI.ApprovalRequiredAIFunction` (also a `DelegatingAIFunction` subclass) is a
**static, per-tool** switch: every call to a tool wrapped in it requires approval, or none do,
decided once at wrap time with no visibility into the actual arguments. ToolGovern's classifier is
a **per-call, argument-aware** verdict -- the same tool can be `Allow` for one call and `Deny` or
`RequireApproval` for the next, based on what the arguments actually target (which path, which
host, which credential). The two compose: wrap a `ToolGovernAIFunction` in an
`ApprovalRequiredAIFunction` (or vice versa) to run both gates.

## Known limitation

The core `ToolDefinition<TResult>.Execute` delegate this class reuses (shared, unmodified, across
the TypeScript/Python/`.NET` ports) has no `CancellationToken` parameter. `ToolGovernAIFunction`
carries the real per-call token through via an `AsyncLocal<CancellationToken>` captured
immediately before invoking the gate -- correct for the normal single-threaded async-await call
chain this wrapper produces, but would not survive a wrapped `AIFunction` that detaches its own
continuation onto a different logical call context (e.g. an inner implementation that does its own
`Task.Run`).

## Upstream issues investigated (.NET)

Root-caused against the real `Microsoft.Agents.AI` / `Microsoft.Extensions.AI.Abstractions` 1.13.0
NuGet packages and the real GitHub issue text, not assumed from the issue title alone.

| # | Reporter | State | Verdict | Notes |
|---|----------|-------|---------|-------|
| [#2254](https://github.com/microsoft/agent-framework/issues/2254) | mokarchi | OPEN | **PARTIAL** | This package IS a real answer to the DX gap mokarchi described: a discoverable, reusable, tested `DelegatingAIFunction` subclass wired to a real classifier, instead of every integrator hand-rolling their own `InvokeCoreAsync` override. It does not resolve the upstream ask itself -- Stephen Toub's own reply in the thread states plainly he does not want this folded into `AIFunctionFactory.Create()`, and the issue is still open with no first-class `builder.AddToolSecurity(...)`-style API landed in the framework. This package is a library users can adopt today; it is not, and does not claim to be, a merged framework-level feature. |
| [#5805](https://github.com/microsoft/agent-framework/issues/5805) | scrodde | OPEN | **FAIL -- N/A** | Root cause is a shallow-clone bug in `PerServiceCallChatHistoryPersistingChatClient.GetStreamingResponseAsync` (`update.Clone()` sharing the `Contents` list reference across FIC's own `FunctionCallContent` -> `ToolApprovalRequestContent` rewrite). This lives entirely inside `Microsoft.Agents.AI`'s own streaming/persistence pipeline, several layers below where a `DelegatingAIFunction` wrapper can observe or intervene. Not reachable from this adapter's layer. |
| [#6882](https://github.com/microsoft/agent-framework/issues/6882) | Oxygen56 | OPEN | **FAIL -- N/A** | About filtering internal tool-call messages out of a *hosted workflow agent's* surfaced response (`AsAIAgent(filterToolCallMessages: true, ...)`, `WorkflowHostAgent`/`WorkflowSession`). This is a workflow-hosting/response-aggregation concern, not a per-call tool-invocation gate. A `DelegatingAIFunction` wrapper has no visibility into how a hosted workflow aggregates or forwards messages after the fact. |
| [#4753](https://github.com/microsoft/agent-framework/issues/4753) | sheng-jie | CLOSED | **FAIL -- N/A** | Root cause was `FunctionInvokingChatClient` batching ALL function calls in a turn into `FunctionApprovalRequestContent` once ANY tool in that turn is approval-required, rather than gating each call independently. That batching logic lives inside FIC's own multi-round tool-calling loop, upstream of where any individual `AIFunction`'s own `InvokeCoreAsync` gets a chance to run. `ToolGovernAIFunction` gates each function's own invocation correctly and independently, but it cannot change how FIC decides which calls to batch into one approval prompt before ever calling any wrapped function -- confirmed closed upstream via a fix inside FIC itself, not reachable by a tool-definition-time wrapper. |
| [#6939](https://github.com/microsoft/agent-framework/pull/6939) | aleks-stefanovic | OPEN | **FAIL -- N/A (correction: not `.NET`)** | Labeled `documentation` and `python`, not `.NET` -- included here in error. It adds `agent-framework-agentsandbox`, a Kubernetes sandboxed code-execution connector for the Python package. Unrelated to tool-call governance/approval in either language. |
| [#6825](https://github.com/microsoft/agent-framework/issues/6825) | Cobra86 | CLOSED | **FAIL -- N/A** | About `ToolApprovalAgent` re-invoking the entire inner agent (and therefore every `AIContextProvider.InvokingAsync`) once per approval batch when auto-approving `AgentSkillsProvider` tools -- an O(rounds) cost-model regression in the approval-agent/context-provider re-invoke pipeline. This is an agent-level orchestration cost problem, not something a per-function `DelegatingAIFunction` wrapper touches; confirmed closed upstream, and confirmed unreachable from this adapter's layer regardless. |

### Summary

Of the six .NET-tagged issues investigated, only **#2254** is actually the shape of problem this
package addresses, and even there the verdict is honestly **PARTIAL**: this package gives
integrators a real, tested, reusable answer today, but does not itself resolve mokarchi's actual
ask (a first-class, framework-shipped API). The other five (#5805, #6882, #4753, #6939, #6825) are
real bugs/features in different layers of `Microsoft.Agents.AI` itself (chat-history persistence,
workflow message aggregation, FIC's own approval-batching logic, an unrelated Python sandbox
connector, and approval-agent re-invoke cost) that a tool-definition-boundary wrapper has no
reach into -- inflating any of them to PASS because "a .NET adapter now exists" would be dishonest
about what this package actually changes.

## What this package does not do

- Does not implement a framework-level `builder.AddToolSecurity(...)` API -- that is the actual,
  still-open ask in #2254; this package is a library-level answer, not a framework change.
- Does not fix FunctionInvokingChatClient's own approval-batching, chat-history persistence, or
  workflow message-filtering behavior (see the issues table above) -- those bugs live below this
  wrapper's reach.
- Does not persist a require-approval decision across a process restart (the same limitation
  `ToolGovern.PendingApprovalRegistry` documents for its core, framework-agnostic use); with no
  `OnApprovalRequired` handler wired into `GovernToolOptions`, a `RequireApproval` verdict fails
  closed (denied), exactly as `ToolGovernMiddleware.GovernTool()` documents.
