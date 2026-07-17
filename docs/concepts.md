# Concepts

## The gate pipeline

`governTool()` / `govern_tool()` wraps a tool definition (`{name, execute}`) and returns a
version that runs every call through this pipeline before the underlying `execute()` runs:

```
call arrives -> resolve effective scope (direct, or via ScopeRegistry) -> classify() against
the 34-rule registry -> aggregate to one decision (deny > require-approval > allow) ->
require-approval calls the approval handler, fail-closed on no handler/timeout/exception ->
write a trace entry (if a TraceWriter is wired in) -> deny raises, allow proceeds to execute()
```

Source: `packages/toolgovern/src/middleware/onToolCall.ts` (TypeScript) and
`toolgovern/middleware/on_tool_call.py` (Python) implement the same pipeline. The Python port is
synchronous; the classifier itself is pure and deterministic in both languages.

## The classifier: 34 rules across 5 categories

| Category | What it covers | Rule count |
| --- | --- | --- |
| TG01 | Shell/process execution risk (`rm -rf`, pipe-to-shell, sudo, chmod 777, fork bombs, reverse shells, disk wipes, decoded-payload execution, context-flooding reads) | 9 |
| TG02 | Filesystem scope escalation (write/delete/chmod/read/symlink outside declared scope, path traversal, sensitive system paths) | 7 |
| TG03 | Undeclared network egress (disabled network, host not in allowlist, raw IP literals, non-standard ports, DNS-exfil patterns, known paste/relay services) | 6 |
| TG04 | Credential/secret access (`.env`, SSH keys, cloud credential files, OS keychains, bulk env dumps, named credentials outside scope) | 6 |
| TG05 | Cross-agent privilege inheritance (unregistered sub-agents, zero-capability grants, requests exceeding what a coordinator actually granted) | 6 |

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

A `ScopeDeclaration` has three fields:

- `network`: `false` (no access), `true` (unrestricted -- discouraged, local/dev use only), or
  an explicit hostname allowlist (subdomains match).
- `filesystem`: a list of path prefixes the agent may read/write/delete under.
- `credentials`: a list of credential identifiers (paths, secret names) the agent may access.

When a coordinator agent spawns a sub-agent, the sub-agent's granted scope is the
**intersection** of what it requests and what its coordinator's own effective scope actually
covers -- never a union, and never an implicit default-allow. An unregistered coordinator yields
the empty scope for its "sub-agent," not unrestricted access. `ScopeRegistry` re-checks this on
every call a TG05 rule evaluates, not just once at spawn time, so a coordinator's scope shrinking
after a sub-agent was spawned is caught on the sub-agent's next call
(`TG05-coordinator-scope-shrunk`).

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

## Policy files

A policy file (`toolgovern.policy.yml`) is a YAML mapping of `scope`, an optional
`defaultDecision` (applied only when no rule fires), and optional `rules.disable` /
`rules.requireApproval` lists of rule IDs. `loadPolicy()` / `load_policy()` parses and validates
in one call, raising with every structural error found (not just the first) if the file is
invalid. See [docs/policy-schema.md](./policy-schema.md) for the full field reference.
