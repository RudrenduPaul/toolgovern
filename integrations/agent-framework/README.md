# toolgovern-integration-agent-framework

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/RudrenduPaul/toolgovern/blob/main/LICENSE)

Route [Microsoft Agent Framework](https://github.com/microsoft/agent-framework) (Python) tool
calls through [toolgovern](https://github.com/RudrenduPaul/toolgovern)'s classifier before they
execute, and surface a `require-approval` verdict through Agent Framework's own
`function_approval_request` / `function_approval_response` flow instead of a separate side
channel.

The toolgovern core is live on PyPI as `toolgovern-cli` (`pip install toolgovern-cli`; the module
you import stays `toolgovern`). This adapter package is not yet
published there; install it from source, which pulls the PyPI core in as a normal dependency:

```bash
git clone https://github.com/RudrenduPaul/toolgovern.git
cd toolgovern
pip install -e integrations/agent-framework
```

See [the root toolgovern README](https://github.com/RudrenduPaul/toolgovern) for why runtime
tool-call governance matters right now.

## Scope and limitations (read this first)

**Python only.** Agent Framework also ships a .NET implementation
(`Microsoft.Agents.AI`); porting this adapter to .NET is a real, separate piece of work (different
tool-definition API, different middleware pipeline, different package ecosystem) and is
explicitly **out of scope for this package**. Every issue investigated below that turned out to
be .NET-specific is called out as such and left for a future .NET port, not silently claimed
fixed.

This package covers three integration points, each backed by a real, running test against the
actual `agent-framework-core` PyPI package:

1. **`governed_function_tool(func, options)`** (`tool.py`) -- wraps a plain callable in a real
   `agent_framework.FunctionTool` whose body is gated by toolgovern's `govern_tool()`. A denied or
   ungranted-approval call never reaches `func`'s real implementation, regardless of whether the
   caller invokes the tool through an agent's function-calling loop or calls `tool.invoke()`
   directly.
2. **`ToolGovernFunctionMiddleware`** (`middleware.py`) -- a `FunctionMiddleware` that classifies
   every call and, for a `require-approval` verdict, produces a real
   `Content.from_function_approval_request(...)` (the same content type Agent Framework's own
   `PolicyEnforcementFunctionMiddleware` uses) instead of toolgovern parking the decision
   somewhere the framework's own approval UI/CLI/session machinery never sees.
3. **`assert_trusted_mcp_streamable_http_source(url, policy)`** (`mcp_trust.py`) -- a
   connection-time origin-allowlist + manifest-signature gate for
   `agent_framework.MCPStreamableHTTPTool`, using toolgovern's own `mcp_trust` module.

## Why two separate gating layers?

Agent Framework's `FunctionTool.approval_mode` is a **static, per-tool** switch: either every call
to that tool requires approval, or none do, decided once before any call to it is even attempted.
toolgovern's classifier is a **per-call, argument-aware** verdict: the same tool can be `allow` for
one call and `require-approval` for another, based on what the actual arguments do (which shell
command, which path, which host, which credential). `governed_function_tool()` and
`ToolGovernFunctionMiddleware` are two independent ways to get toolgovern's per-call verdict
applied on top of (not instead of) Agent Framework's own static gate; use either or both.

## Quick example: `governed_function_tool`

```python
import asyncio
from toolgovern import GovernToolOptions, ScopeDeclaration, ToolGovernDenialError
from toolgovern_integration_agent_framework import governed_function_tool


def read_file(path: str) -> str:
    with open(path) as f:
        return f.read()


tool = governed_function_tool(
    read_file,
    GovernToolOptions(
        scope=ScopeDeclaration(filesystem=["/workspace"]),
        agent_id="research-agent",
    ),
    description="Read a file from the workspace.",
)


async def main() -> None:
    # Inside the declared scope -- executes for real.
    result = await tool.invoke(arguments={"path": "/workspace/notes.txt"})
    print(result)

    # Outside the declared scope -- denied before read_file() ever runs.
    try:
        await tool.invoke(arguments={"path": "/etc/passwd"})
    except ToolGovernDenialError as error:
        print(f"blocked: {error}")


asyncio.run(main())
```

## Quick example: `ToolGovernFunctionMiddleware`

```python
from agent_framework import Agent, Content, FunctionInvocationContext
from toolgovern import Policy, ScopeDeclaration
from toolgovern_integration_agent_framework import ToolGovernFunctionMiddleware

policy = Policy(scope=ScopeDeclaration(network=["api.example.com"]), agent_id="assistant")
governance = ToolGovernFunctionMiddleware(policy)

agent = Agent(client=client, name="assistant", tools=[my_tool], middleware=[governance])
# A call the classifier marks require-approval now produces a real
# function_approval_request on agent.run(...)'s response -- handle it exactly like any other
# Agent Framework approval request (show it to a user, collect a function_approval_response,
# send that back in the next turn). governance resolves it against toolgovern's own
# PendingApprovalRegistry and only then lets the real call through.
```

## Quick example: MCP server trust gate

```python
from agent_framework import MCPStreamableHTTPTool
from toolgovern import McpTrustPolicy, PinnedPublicKey
from toolgovern_integration_agent_framework import assert_trusted_mcp_streamable_http_source

policy = McpTrustPolicy(
    allowed_origins=["mcp.example.com"],
    pinned_keys=[PinnedPublicKey(key_id="prod-2026", algorithm="ed25519", public_key_pem=PEM)],
)

url = "https://mcp.example.com/manifest"
assert_trusted_mcp_streamable_http_source(url, policy)  # raises McpServerNotTrustedError if not trusted
mcp_tool = MCPStreamableHTTPTool(name="example", url=url)
```

## Install for development / running the tests

```bash
cd integrations/agent-framework
pip install -e ../../python           # toolgovern core, editable, from this monorepo
pip install -e .[dev]
pytest
```

(This installs the toolgovern core in editable mode from the monorepo's `python/` directory so
local core changes are picked up immediately. For a normal, non-editable install, `pip install
toolgovern` from PyPI satisfies the same `dependencies = ["toolgovern>=0.1.0,<0.2", ...]` pin in
`pyproject.toml`.)

## Upstream issues investigated

Root-caused against the real `agent-framework` source (installed from PyPI, version 1.11.0 at the
time of writing) and the real GitHub issue/PR text, not assumed from the issue title alone.

| # | Reporter | Verdict | Notes |
|---|----------|---------|-------|
| [#5494](https://github.com/microsoft/agent-framework/pull/5494) | chetantoshniwal | **PARTIAL** | Confirmed Python-side, confirmed still a real gap: `FunctionTool.invoke()` in the installed 1.11.0 source has no `approval_mode` check at all -- that check exists only in `_try_execute_function_calls()`, so a direct `tool.invoke()` call bypasses Agent Framework's own approval gate entirely. The proposed fix PR was **closed without being merged** (`mergedAt: null`) -- this is a real, still-open upstream gap, not something this adapter can patch inside `agent_framework` itself. `governed_function_tool()` provides a genuine mitigation *for tools built with it*: toolgovern's own gate lives inside the wrapped callable's body, so it still runs even when Agent Framework's own `approval_mode` check is bypassed this way. It does not fix `FunctionTool.invoke()` for tools *not* built with this adapter. |
| [#6910](https://github.com/microsoft/agent-framework/issues/6910) | antsok | **PARTIAL** | Confirmed Python-side (`packages/ag-ui/...`, `packages/core/agent_framework/_tools.py`), closed as completed upstream. Root cause: the AG-UI host constructs a fresh `AgentSession` per HTTP request, destroying the `session.state["tool_approval"]` bookkeeping Agent Framework's core parks parallel-call approval state in. `ToolGovernFunctionMiddleware`'s pending-approval bookkeeping (`_tracked`, backed by toolgovern's `PendingApprovalRegistry`) lives on the middleware instance, not in `session.state`, so it does not lose state across a fresh-session-per-request host **for calls gated through this middleware**. This is an architectural side-step for toolgovern-gated calls, not a fix to the underlying AG-UI/session-state bug for Agent Framework's own native approval flow in general -- no AG-UI host repro was built or run as part of this package. |
| [#5914](https://github.com/microsoft/agent-framework/issues/5914) | finnoybu | **FAIL -- N/A (out of scope for this adapter's layer)** | Confirmed as predicted: this asks for `origin_session_id`-style cross-session memory attribution at the context-provider/session layer (`SessionContext.extend_messages`, `_harness/_memory.py`). Confirmed **not present** in the installed 1.11.0 source (`grep -r origin_session_id` finds nothing) despite the issue showing `closedAt`/`stateReason: COMPLETED`. This is a different layer than tool-call gating -- a `FunctionMiddleware`/`FunctionTool` wrapper has no visibility into which session a `ContextProvider` originally wrote a memory in. Not fixable from this adapter; a real fix belongs in `agent_framework`'s own context-provider/session code, exactly as the issue proposes. |
| [#6171](https://github.com/microsoft/agent-framework/pull/6171) | shrutitople | **PASS (N/A -- already resolved upstream via a parallel mechanism)** | MERGED. This is Agent Framework's own native FIDES information-flow-control feature (MCP-annotation-based tool/result labeling). It is a parallel, coexisting mechanism to toolgovern's own TG08 IFC classifier, not a gap toolgovern needs to fill. No code change needed; both can run layered (toolgovern's `IfcPolicy` check in `classify()`, Agent Framework's own FIDES labels), since neither depends on the other. |
| [#6860](https://github.com/microsoft/agent-framework/pull/6860) | shrutitople | **PASS (N/A -- already resolved upstream via a parallel mechanism)** | Same relationship as #6171: a sample/doc PR for Agent Framework's own FIDES gateway-delegated IFC policy evaluation. Independent of toolgovern's TG08; no fix needed from this adapter. |
| [#5864](https://github.com/microsoft/agent-framework/issues/5864) | lirik173 | **PASS** | OPEN, labeled both `python` and `.NET` (genuinely cross-cutting, not purely one or the other). Confirmed: Agent Framework has no built-in MCP-server allowlist/signature-verification primitive at any `MCPClient`-family construction boundary. toolgovern's `mcp_trust` module already implements exactly this primitive. `assert_trusted_mcp_streamable_http_source()` wires it to `MCPStreamableHTTPTool`'s connection URL, tested against both an allowed and a denied case. This does not fix the upstream framework gap (the issue stays open; Agent Framework itself still has no native equivalent) -- it lets a toolgovern user get the primitive today without waiting for it. |

### Additional issues confirmed out of scope (future .NET-port candidates)

| # | Reporter | Labels (actual, verified via `gh issue view`) | Confirmation |
|---|----------|-----------------------------------------------|--------------|
| [#5805](https://github.com/microsoft/agent-framework/pull/5805) | scrodde | `question`, `.NET` | Genuinely .NET-only (`PerServiceCallChatHistoryPersistingChatClient` is a .NET-side chat client type). |
| [#6882](https://github.com/microsoft/agent-framework/pull/6882) | Oxygen56 | `.NET`, `workflows` | Genuinely .NET-only. |
| [#4753](https://github.com/microsoft/agent-framework/issues/4753) | sheng-jie | `bug`, `.NET`, `reproduced` | Genuinely .NET-only. |
| [#2254](https://github.com/microsoft/agent-framework/issues/2254) | mokarchi | `.NET` | Genuinely .NET-only. Notable: this is the .NET-side feature request for approximately what this package builds for Python (`FunctionMiddleware`-based security/validation gating) -- a real candidate starting point for a future .NET port. |
| [#6825](https://github.com/microsoft/agent-framework/issues/6825) | Cobra86 | `.NET` | Genuinely .NET-only, closed. |
| [#6939](https://github.com/microsoft/agent-framework/pull/6939) | aleks-stefanovic | `python`, `documentation` (**not** `.NET`) | Labeled `python`, not `.NET`, despite initially looking like a .NET-only item. It is out of scope for a different reason -- it adds an unrelated Kubernetes sandbox code-execution connector (`agent-framework-agentsandbox`), not a tool-governance/approval concern this adapter addresses. Flagged here rather than silently reclassified. |
| [#6693](https://github.com/microsoft/agent-framework/pull/6693) | taisirhassan | `.NET`, `python`, `documentation` (**dual-tagged, not purely `.NET`**) | Labeled both `.NET` and `python`, MERGED. About Microsoft Purview identity-principal resolution, unrelated to toolgovern's own caller-asserted `agent_id` model or tool-call gating -- out of scope for this adapter regardless of language tagging. |

## What this package does not do

- No .NET support (see "Scope and limitations" above).
- Does not persist `ToolGovernFunctionMiddleware`'s pending-approval bookkeeping across a process
  restart -- the same limitation `toolgovern.PendingApprovalRegistry` documents for its core,
  framework-agnostic use.
- Does not automatically run the MCP trust gate on every `MCPStreamableHTTPTool` construction --
  it is an explicit call the integrator makes before constructing the tool, not a monkey-patch.
- Does not cover Agent Framework's `MCPStdioTool` (local-subprocess transport) -- the trust model
  toolgovern's `mcp_trust` module implements (origin allowlist + manifest signature) is specific to
  a network-reachable server; a stdio server has a different trust boundary.
