# Concepts

## The gate pipeline

`governTool()` / `govern_tool()` wraps a tool definition (`{name, execute}`) and returns a
version that runs every call through this pipeline before the underlying `execute()` runs:

```
call arrives -> resolve effective scope (direct, or via ScopeRegistry) -> classify() against
the 35-rule registry -> aggregate to one decision (deny > require-approval > allow) ->
require-approval calls the approval handler, fail-closed on no handler/timeout/exception ->
write a trace entry (if a TraceWriter is wired in) -> deny raises, allow proceeds to execute()
```

Source: `packages/toolgovern/src/middleware/onToolCall.ts` (TypeScript) and
`toolgovern/middleware/on_tool_call.py` (Python) implement the same pipeline. The Python port is
synchronous; the classifier itself is pure and deterministic in both languages.

## The classifier: 35 rules across 6 categories

| Category | What it covers                                                                                                                                                     | Rule count |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------- |
| TG01     | Shell/process execution risk (`rm -rf`, pipe-to-shell, sudo, chmod 777, fork bombs, reverse shells, disk wipes, decoded-payload execution, context-flooding reads) | 9          |
| TG02     | Filesystem scope escalation (write/delete/chmod/read/symlink outside declared scope, path traversal, sensitive system paths)                                       | 7          |
| TG03     | Undeclared network egress (disabled network, host not in allowlist, raw IP literals, non-standard ports, DNS-exfil patterns, known paste/relay services)           | 6          |
| TG04     | Credential/secret access (`.env`, SSH keys, cloud credential files, OS keychains, bulk env dumps, named credentials outside scope)                                 | 6          |
| TG05     | Cross-agent privilege inheritance (unregistered sub-agents, zero-capability grants, requests exceeding what a coordinator actually granted)                        | 6          |
| TG08     | Information-flow control (a call reading a caller-declared confidential-or-higher source and writing/sending to a lower- or undeclared-trust sink)                 | 1          |

Every fired rule carries a `ruleId`, a `decision` (`deny` or `require-approval` -- a rule never
returns `allow`; it either fires or it doesn't), a human-readable `reason`, and the argument
that tripped it. `classify()` runs the whole registry and returns the single most severe
decision found (`deny` > `require-approval` > `allow`) plus the full list of fired rules -- there
is no unexplained denial: if `firedRules`/`fired_rules` is empty, the decision can only be
`allow`.

Text-matching rules (TG01 shell patterns, TG04 credential patterns, TG03 host extraction) run
input through a normalization pass first (Unicode NFKC, invisible-format-character stripping,
`$IFS`-as-space collapsing, empty-quote-pair collapsing) so a handful of known obfuscation
tricks -- `r""m -rf /`, `rm${IFS}-rf${IFS}/`, a zero-width space spliced into `curl` -- can't
dodge a literal-substring match. This is a per-call regex classifier, not a shell-grammar parser
or an AST-based static analyzer -- see [docs/security-model.md](./security-model.md) for exactly
what obfuscation shapes remain out of scope.

## Scope declaration and default-deny inheritance

A `ScopeDeclaration` has four fields:

- `network`: `false` (no access), `true` (unrestricted -- discouraged, local/dev use only), or
  an explicit hostname allowlist (subdomains match).
- `filesystem`: a list of path prefixes the agent may read/write/delete under.
- `credentials`: a list of credential identifiers (paths, secret names) the agent may access.
- `ifc` (optional): a caller-declared confidentiality/trust labeling policy TG08 evaluates -- see
  below. Omitted entirely (the default) means TG08 never fires for this agent.

When a coordinator agent spawns a sub-agent, the sub-agent's granted scope is the
**intersection** of what it requests and what its coordinator's own effective scope actually
covers -- never a union, and never an implicit default-allow. An unregistered coordinator yields
the empty scope for its "sub-agent," not unrestricted access. `ScopeRegistry` re-checks this on
every call a TG05 rule evaluates, not just once at spawn time, so a coordinator's scope shrinking
after a sub-agent was spawned is caught on the sub-agent's next call
(`TG05-coordinator-scope-shrunk`).

## TG08: information-flow control

Every rule above answers "should this call happen" -- is this argument dangerous, is this
path/host/credential in scope. TG08 answers a categorically different question: **can this
_data_ flow here?** Microsoft Agent Framework's FIDES answers the fuller version of that question
with a confidentiality-label lattice tracked across an entire MCP gateway boundary. TG08 is
deliberately not that -- it is the smallest real primitive that lets a genuine label-propagation
check exist at all, scoped down to one call at a time.

**The labeling API.** `ConfidentialityLabel` is a fixed, closed, ordered set: `'public'` <
`'internal'` < `'confidential'` < `'restricted'`. `IfcPolicy` (`ScopeDeclaration.ifc`) is what the
caller declares once per agent:

```ts
scope: {
  network: false,
  filesystem: [],
  credentials: [],
  ifc: {
    sources: { 'db.customers': 'confidential' },
    sinkTrust: { 'internal.dashboard': 'confidential', 'public.webhook': 'public' },
  },
}
```

`TG08-confidential-source-to-untrusted-sink` fires when a call's `source`/`from`/`sourceId`/
`readFrom` argument names a resource labeled confidential-or-higher in `ifc.sources`, AND its
`sink`/`to`/`destination`/`sendTo`/`forwardTo` argument names a destination whose declared
`ifc.sinkTrust` tier is lower than the source's label -- `deny` -- **or whose trust tier isn't
declared in `sinkTrust` at all** -- `require-approval`, never a silent `allow`. This is the one
property the rule commits to: an undeclared destination is treated as ambiguous, not trusted.

**What this deliberately does NOT do**, disclosed rather than hidden -- see
`classifier/information-flow.ts` / `classifier/information_flow.py`'s module docstring for the
full writeup:

- **No automatic label inference.** toolgovern cannot know that an argument is confidential or
  that a destination is untrusted from the argument alone -- `sources`/`sinkTrust` are a real,
  hand-declared labeling API the caller must maintain, not something this rule derives on its own.
- **No cross-call taint tracking.** Each call is evaluated in isolation. If confidential data
  read in one call is only handed to an untrusted sink two calls later, TG08 does not see that --
  a real IFC system tracks a label across an entire flow graph, this evaluates one call's own
  source/sink arguments.
- **No reader/principal-scoped lattice.** One flat total order, not a set of readers or a
  join/meet lattice over multiple simultaneous principals.
- **No result-value inspection.** This evaluates a call's declared arguments, not the data a tool
  call actually returns.

## The signed local audit trail

Every gate decision -- `allow`, `deny`, or `require-approval` -- is written as one line of a
JSON Lines file. Each entry's `signature` is either:

- **`sha256:<hex>`** (the default) -- an unkeyed content hash proving the entry has not changed
  since it was written, but reproducible by anyone with no secret required. It does **not** stop
  someone with write access to the trace file from editing an entry and recomputing a signature
  that still verifies.
- **`hmac-sha256:<hex>`** (opt-in, via a `secretKey`/`secret_key`) -- only someone holding the
  same key can produce a signature that verifies. toolgovern does not generate, store, or rotate
  this key; that is the caller's responsibility.

`prior_trace_id` chains each entry to the one before it in the same session, so a reader
(`verifyChain()` / `verify_chain()`) can detect a missing, reordered, or tampered entry, in
addition to a signature mismatch. See [docs/trace-format.md](./trace-format.md) for the full
field reference and [docs/security-model.md](./security-model.md) for the residual limitations
of both signing modes.

## MCP-server trust boundary (connection-time, not per-call)

Everything above -- the classifier, scoping, the trace -- runs _after_ an MCP server's tools are
already trusted and being called. `mcp-trust/index.ts` / `mcp_trust/__init__.py` is a separate,
standalone module answering a categorically different question, once, before that point: should
this agent connect to this MCP server, and trust the tool definitions it declares, at all?

- `isOriginAllowed(origin, allowlist)` / `is_origin_allowed(...)` -- an explicit allowlist checked
  once per connection. Exact match by default (not subdomain trust, unlike TG03's own host
  matching); a leading `*.` allowlist entry opts a domain into subdomain matching explicitly.
- `verifyMcpServerManifest(...)` / `verify_mcp_server_manifest(...)` -- verifies a fetched (or
  directly-supplied) manifest's detached Ed25519 or RSA-SHA256 signature against a pinned
  public-key list before any tool it declares is trusted.
- `assertMcpServerTrusted(...)` / `assert_mcp_server_trusted(...)` -- combines both into one gate.

All three fail closed: an unreachable manifest, an unverified signature, an unknown key ID, or an
origin not on the allowlist all deny, never silently allow. See
[docs/security-model.md](./security-model.md) (finding #11) for what this does and does not cover
-- notably, no sigstore/keyless verification and no post-connection re-verification.

## Policy files

A policy file (`toolgovern.policy.yml`) is a YAML mapping of `scope`, an optional
`defaultDecision` (applied only when no rule fires), and optional `rules.disable` /
`rules.requireApproval` lists of rule IDs. `loadPolicy()` / `load_policy()` parses and validates
in one call, raising with every structural error found (not just the first) if the file is
invalid. See [docs/policy-schema.md](./policy-schema.md) for the full field reference.
