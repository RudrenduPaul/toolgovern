# ToolGovern .NET port

A faithful .NET 10 port of ToolGovern's core: the multi-rule risk classifier (TG01-TG05, TG08),
the intersection-only scope registry, the signed hash-chained trace, and the `GovernTool()`
pre-execution middleware gate. Ported from the TypeScript original (`packages/toolgovern/`) and
cross-checked against the Python port (`python/src/toolgovern/`) so the same behavior and the same
failure-closed defaults apply identically in .NET.

## Why this exists

Microsoft Agent Framework 1.0 (GA 2026-04-03, unifying AutoGen + Semantic Kernel) ships
first-class .NET support, and several real GitHub issues against `microsoft/agent-framework` are
explicitly .NET-specific (tool-call governance, approval workflows, cross-agent scoping). This port
closes that gap for teams building on the .NET side of Agent Framework, giving ToolGovern genuine
cross-framework portability rather than a TypeScript/Python-only reach.

**Honest scope note:** Microsoft also shipped its own first-party "Agent Governance Toolkit" for
Agent Framework in April 2026 -- a native policy engine with sub-millisecond latency. This port is
not positioned to out-compete that native tool on Agent Framework specifically. It exists to close
real, already-filed GitHub issues and to give ToolGovern users a consistent governance layer when
part of their stack is .NET and part is TypeScript/Python (a coordinator in one language spawning
sub-agents in another, for example), and for any other .NET-based agent runtime that isn't Agent
Framework itself.

## Structure

```
dotnet/ToolGovern/
  ToolGovern.slnx                  solution file
  src/ToolGovern/                  class library (PackageId: ToolGovern.Net)
    Types.cs                       Decision, ScopeDeclaration, RuleContext, RuleMatch, TraceEntry, ...
    Shared/PathUtil.cs              path/host normalization (paths.ts port)
    Classifier/                     TG01-TG05 + TG08 rule packs, the classifier engine
    Scoping/                        ScopeRegistry, default-deny inheritance
    Trace/                          canonical JSON, signed hash-chained trace writer/reader
    Approval/                       durable PendingApprovalRegistry
    Middleware/                     GovernTool(), IdempotencyCache, ResumePendingApproval()
  test/ToolGovern.Tests/            xUnit test suite mirroring the TS/Python test scenarios
```

## What was ported faithfully

- **Classifier** (`Classifier/`): all ~36 rules across TG01 (shell/process risk), TG02
  (filesystem scope escalation), TG03 (undeclared network egress, including the async
  DNS-resolution-to-private-address check), TG04 (credential/secret access), TG05 (cross-agent
  privilege inheritance), and TG08 (information-flow control) -- same rule IDs, same regex
  patterns (ported to `GeneratedRegex` for AOT-friendly compiled regex), same obfuscation
  normalization (Unicode NFKC, `$IFS`-as-space, empty-quote-pair collapsing), same fail-closed
  defaults.
- **Scoping** (`Scoping/`): `ScopeRegistry`'s intersection-only default-deny inheritance --
  a sub-agent's granted scope is always the intersection of what it requested and what its
  coordinator actually has, computed identically (including the narrower-host-wins network
  intersection logic) to the TypeScript original.
- **Trace** (`Trace/`): canonical (sorted-key) JSON serialization, `sha256:`/`hmac-sha256:`
  signed, hash-chained (`prior_trace_id`) trace entries, including `agent_id_source` and
  `approved_by` optional-field semantics (omitted, not null, when absent -- matching the
  TypeScript port's `JSON.stringify` `undefined`-drops-the-key behavior).
- **Middleware** (`Middleware/`): `GovernTool()`'s full pre-execution gate -- classify, fail-closed
  approval resolution with a timeout, durable `PendingApprovalRegistry` wiring (register-before-
  invoke, alias tolerance, edited-args re-classification), the in-memory idempotency cache, and
  `ResumePendingApproval()` for the async-resume path.

## Building and testing

```bash
cd dotnet/ToolGovern
dotnet build ToolGovern.slnx
dotnet test ToolGovern.slnx
dotnet pack src/ToolGovern/ToolGovern.csproj -c Release   # produces ToolGovern.Net.<version>.nupkg
```

`dotnet nuget push` is intentionally never run from this repo -- publishing is a separate,
deliberate step.

## Known limitations (disclosed, not hidden)

- This is a source port, not yet published to NuGet.
- The DNS-resolution check (`TG03-dns-resolves-private`) narrows but does not eliminate
  DNS-rebinding TOCTOU, exactly like the TypeScript/Python originals -- see those ports' own
  security-model notes for the full reasoning.
- `PendingApprovalRegistry` and `IdempotencyCache` are in-memory-only, scoped to a single process
  -- the same explicitly-disclosed scope as the originals, not a regression introduced by this port.
- Agent identity (`AgentId`) remains a caller-asserted string, never cryptographically verified --
  `ScopeDeclarationHelpers.IsValidAgentId` is a format/hygiene check, not authentication.
