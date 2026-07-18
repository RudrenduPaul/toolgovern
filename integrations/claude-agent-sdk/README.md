# toolgovern-integration-claude-agent-sdk

[![PyPI version](https://img.shields.io/pypi/v/toolgovern-integration-claude-agent-sdk.svg)](https://pypi.org/project/toolgovern-integration-claude-agent-sdk/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/RudrenduPaul/toolgovern/blob/main/LICENSE)

Route [Claude Agent SDK](https://github.com/anthropics/claude-agent-sdk-python) tool calls through
[toolgovern](https://pypi.org/project/toolgovern/)'s `classify()` gate via a real `PreToolUse`
hook -- shell, filesystem, network, and credential access evaluated (allow, deny, or
require-approval) before the SDK lets a tool run, with no per-tool wrapping required.

```bash
pip install toolgovern-integration-claude-agent-sdk claude-agent-sdk toolgovern
```

## Why this package exists

Real market signal (2025-07 onward) shows `claude-agent-sdk` passing AutoGen in enterprise
production-deployment count in early-to-mid 2026 -- and until this package, it had zero toolgovern
coverage. Its `PreToolUse` hook is also, mechanically, the cleanest governance seam toolgovern has
adapted to yet: it fires before *any* tool executes, receives the exact tool name and input the
model is about to invoke, and returns a structured permission decision (`allow` / `deny` / `ask` /
`defer`) that the CLI itself enforces -- no framework fork, no per-tool wrapper call site to get
right or accidentally miss.

This was verified against the real installed package (`pip install claude-agent-sdk`, v0.2.122 at
the time of writing) by reading `claude_agent_sdk/types.py` directly, not a docs summary:

- `HookCallback = Callable[[HookInput, str | None, HookContext], Awaitable[HookJSONOutput]]` --
  the callback the SDK calls is `async`, even though `PreToolUse` blocks the tool call on its
  result from the framework's point of view. This package's hook is `async def` accordingly.
- `PreToolUseHookInput` carries `tool_name: str` and `tool_input: dict[str, Any]` -- exactly the
  `(tool, args)` shape `toolgovern.classify()` already evaluates.
- The hook returns a `hookSpecificOutput` dict with `permissionDecision` and an optional
  `permissionDecisionReason` -- this package emits `"allow"` or `"deny"` (never a bare
  pass-through to the CLI's own `"ask"` UI for a require-approval verdict; see below).

## Quick example

```python
import asyncio
from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient, HookMatcher
from toolgovern import ScopeDeclaration
from toolgovern_integration_claude_agent_sdk import GovernedHookOptions, governed_pretooluse_hook

hook = governed_pretooluse_hook(
    GovernedHookOptions(
        scope=ScopeDeclaration(filesystem=["/workspace"], network=["api.internal.example.com"]),
        agent_id="research-sub",
        session_id="demo-session",
    )
)

options = ClaudeAgentOptions(
    hooks={"PreToolUse": [HookMatcher(hooks=[hook])]},
)

async def main():
    async with ClaudeSDKClient(options=options) as client:
        await client.query("List the files in /workspace, then read ~/.ssh/id_rsa")
        async for message in client.receive_response():
            print(message)

asyncio.run(main())
```

The second request in that example -- reading `~/.ssh/id_rsa` -- is denied before the SDK's Bash
tool ever runs: `TG04-ssh-key-access` fires, the hook returns `permissionDecision: "deny"`, and the
CLI surfaces that denial back to the model instead of executing the command.

## Require-approval: no in-hook "pause and wait for a human"

A `PreToolUse` hook has no built-in notion of pausing a run for asynchronous human review the way
a LangGraph interrupt does -- once the coroutine returns, the CLI acts on the decision immediately.
So a `require-approval` classifier verdict is wired to the same durable, resumable approval
registry the rest of toolgovern ships (`toolgovern.PendingApprovalRegistry`,
`toolgovern.resume_pending_approval()`):

1. The decision is registered in a `PendingApprovalRegistry` *before* anything else happens, so a
   durable record exists regardless of what happens next.
2. If you supply `on_approval_required` (an `async` callable, bounded by `approval_timeout_s`) and
   it genuinely answers in time, that answer is the final decision and the registry entry is
   closed out as resolved.
3. If there is no handler, the handler raises, or it does not answer in time, the hook **fails
   closed**: the call is denied, and the reason names the pending-approval id so a human (or a
   webhook / CLI command / review-queue worker) can resolve it later, out of band, via
   `PendingApprovalRegistry.resolve_pending()` or `toolgovern.resume_pending_approval()`.

```python
from toolgovern import PendingApprovalRegistry

registry = PendingApprovalRegistry()

async def ask_slack(info):
    # Real implementations post to a review queue and await its resolution (bounded by
    # approval_timeout_s below); this toy example just denies everything synchronously.
    return False

hook = governed_pretooluse_hook(
    GovernedHookOptions(
        scope=ScopeDeclaration(),
        pending_approvals=registry,
        on_approval_required=ask_slack,
        approval_timeout_s=30.0,
    )
)
```

## API

### `governed_pretooluse_hook(options: GovernedHookOptions) -> HookCallback`

Builds a real `PreToolUse` `HookCallback`. `options` is a `GovernedHookOptions` -- the same shape
as `toolgovern.GovernToolOptions` (the tool-wrapper's options), minus the fields that only make
sense for wrapping a tool's execution (`idempotency`, `on_tool_result`), plus the two a hook needs
instead: `on_approval_required` (an async approval handler) and `approval_timeout_s` (seconds,
matching `asyncio`'s convention, rather than `GovernToolOptions.approval_timeout_ms`).

Register it exactly once per `ClaudeAgentOptions`/`ClaudeSDKClient` under the `"PreToolUse"` key:

```python
ClaudeAgentOptions(hooks={"PreToolUse": [HookMatcher(hooks=[hook])]})
```

### `GovernedHookOptions`

`scope`, `agent_id`, `session_id`, `coordinator_id`, `rules`, `default_decision`, `policy`,
`name` -- identical semantics to `toolgovern.GovernToolOptions`. `scope_registry` and `trace` wire
in the same `ScopeRegistry` / `TraceWriter` a `govern_tool()`-based part of your stack already
uses, so a mixed deployment (some tools wrapped with `govern_tool()`, the Claude Agent SDK gated
via this hook) shares one scope-inheritance registry and one audit trail. `GovernedHookOptions.
from_policy(policy, **overrides)` builds one straight from a `toolgovern.load_policy()` result,
same as `GovernToolOptions.from_policy()`.

## What this does not claim

This package adds new Claude Agent SDK capability -- it does not retroactively fix any previously
reported issue; there was no prior GitHub issue to validate against, since this integration did
not exist before. It also does not populate the SDK's `updatedInput` hook field (the SDK's
documented "modify input before execution" capability): toolgovern's classifier is a pure gate, it
does not rewrite tool arguments, so there is nothing genuine to put there in this pass.

See the [full toolgovern documentation](https://github.com/RudrenduPaul/toolgovern) on GitHub for
the classifier, the rule pack, and the trace format spec.

## License

Apache 2.0. See [LICENSE](https://github.com/RudrenduPaul/toolgovern/blob/main/LICENSE).
