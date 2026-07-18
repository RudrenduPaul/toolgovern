# Changelog

All notable changes to this project are documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Python 0.1.0] - 2026-07-16

A genuine Python port of `packages/toolgovern` and `packages/toolgovern-cli` -- not a wrapper
around the Node binary. Code-complete, fully tested, and built; PyPI publish is pending a
platform-side throttle on this account (`429 Too many new projects created`) rather than any
issue with the package itself -- see the PR for the real-time status.

### Added

- `toolgovern`, built and ready for PyPI: the full 34-rule classifier (TG01 9 rules, TG02 7,
  TG03 6, TG04 6, TG05 6), ported rule-for-rule with the same regex patterns, obfuscation-resistance normalization
  (`normalize_for_match`), and ReDoS-safe `rm -rf` pattern as the TypeScript original
- `ScopeRegistry` / `compute_inherited_scope` -- the same default-deny, intersection-only scope
  inheritance model, including the coordinator-scope-shrinks re-check
- `TraceWriter` / `read_trace` / `verify_chain` -- the same signed, append-only JSON Lines trace
  format: unkeyed `sha256:` content hash by default, optional `hmac-sha256:` keyed signing via
  `secret_key`, constant-time signature comparison (`hmac.compare_digest`)
- `load_policy` / `validate_policy` -- the same YAML policy schema and validation rules,
  including full-error-list reporting and rule-ID reference checking against the real registry
- `govern_tool()` -- the same gate pipeline (classify -> approval flow with fail-closed
  timeout/exception handling -> trace write -> deny raises / allow executes), including the
  optional in-memory idempotency cache and `on_tool_result` post-execution hook
- `toolgovern-cli` console script: `validate <policy-file>` and
  `audit <trace-file> [--since] [--decision] [--agent] [--rule] [--verify-chain] [--key-file]`,
  both with a `--json` structured-output mode matching the npm CLI's envelope shape
- 237 pytest tests covering all 5 rule categories (with true/false-positive cases per rule,
  obfuscation-resistance regressions, and a ReDoS timing regression test), scope-inheritance
  edge cases, both trace signing schemes (including a dedicated test proving the unkeyed
  scheme's forgeability and the keyed scheme closing that gap), policy validation, the full
  `govern_tool()` middleware (approval flow, fail-closed timeout, throwing-handler regression,
  idempotency, `on_tool_result`), and both CLI subcommands
- `python/docs/getting-started.md`, `docs/concepts.md`, `docs/integrations/ci.md` -- shared
  docs covering both distributions
- `python/examples/` -- 3 runnable examples: gating a tool, scope-inheritance intersection, and
  signed-trail writing/verification (both signing modes, including a live tamper demonstration)

### Fixed

- `python/README.md`: added a "Why this exists" section (the runtime-governance gap the 34-rule
  classifier, intersection-only scope inheritance, and signed audit trail close), matching the
  structure of sibling package READMEs. Docs-only; still pre-publish, so this stays 0.1.0 rather
  than bumping -- the stored wheel/sdist waiting on PyPI's new-project throttle to clear were
  rebuilt from this corrected README before being retried.

### Known scope limitation (disclosed, not a gap in the port)

- `toolgovern-cli init [oma|langgraph]` (the npm CLI's TypeScript integration-file scaffolder)
  is intentionally **not** ported -- it generates a `.ts` file importing
  `toolgovern-integration-langgraph`/`toolgovern-integration-oma`, both JS/TS packages. This is
  out of scope for a Python port by nature, not an oversight; `validate` and `audit` are
  otherwise behaviorally equivalent (including `--json` output shape) between both CLIs.
- The `toolgovern-integration-langgraph` and `toolgovern-integration-oma` npm packages are not
  ported to Python in this release. Both are thin wrapper packages in the TS source (roughly
  170 combined lines, no independent governance logic -- everything routes through
  `governTool()`/`govern_tool()` in core) and are tracked as a follow-up, not because porting
  them is hard, but to keep this first PyPI release scoped to the governance engine core.

## [Unreleased]

### Added

- `TG08-confidential-source-to-untrusted-sink` -- a new rule category, information-flow control:
  fires when a call reads from a source labeled confidential-or-higher (caller-declared via a new
  `IfcPolicy`/`ScopeDeclaration.ifc` field, a hand-declared labeling API, not automatic inference)
  and writes/sends to a destination whose declared trust tier is lower (`deny`) or was never
  declared at all (`require-approval`, fail-closed on ambiguity, never a silent `allow`). New
  `ConfidentialityLabel` closed type (`public < internal < confidential < restricted`) in
  `types.ts`/`types.py`. Ported to both languages (`classifier/information-flow.ts` /
  `classifier/information_flow.py`), bringing the synchronous rule count to 35 (TS) / 36 (Python,
  which also folds in `TG03-dns-resolves-private`). Scoped deliberately against
  [microsoft/agent-framework#6171](https://github.com/microsoft/agent-framework/pull/6171) and
  [#6860](https://github.com/microsoft/agent-framework/pull/6860) (both shrutitople): this is the
  smallest real primitive that lets a genuine label-propagation check exist, not a reimplementation
  of FIDES's automatic MCP-annotation labeling, gateway-delegated policy evaluation, or
  readers-lattice label type -- see `docs/security-model.md` finding #12 for the full, honest
  comparison against what those two PRs actually deliver.
- `TG03-dns-resolves-private` -- closes the TG03 network-egress sub-gap where a **hostname**
  argument that _resolves_ to a loopback/RFC1918/link-local/cloud-metadata address (e.g.
  `internal-alias.attacker.io -> 127.0.0.1`) sailed through undetected, since the existing
  `TG03-raw-ip-literal` rule only ever inspected the literal argument string, never performed a
  DNS lookup. TypeScript: resolves via `dns.promises.lookup()` in a new async-only
  `TG03-dns-resolves-private` rule, evaluated by a new `classifyAsync()` (`governTool()`'s already-
  async `execute()` now calls this instead of the synchronous `classify()`); the pre-existing
  34-rule synchronous `classify()`/`ruleRegistry` is unchanged and does not run this one
  DNS-dependent rule. Python: resolves via `socket.getaddrinfo()` as an ordinary synchronous member
  of the single `rule_registry`/`classify()` (35 rules total there), since `govern_tool()` is
  synchronous end to end in that port. Both sides fail closed (`require-approval`, never `allow`)
  on a DNS-resolution failure, empty result set, or timeout (3s, matching the existing approval-
  timeout idiom). Disclosed, not claimed as complete: this narrows but does not eliminate
  DNS-rebinding TOCTOU (an attacker can still change the DNS answer between this check and the
  tool's own HTTP client connecting), and HTTP redirect-chain revalidation remains a separate,
  still-open gap requiring runtime visibility into the tool's actual HTTP client -- see
  `docs/security-model.md` finding #10 for the full writeup, including scoped confirmation (each PR/
  issue actually read via `gh pr view`/`gh issue view`, not assumed) against
  [microsoft/autogen#7706](https://github.com/microsoft/autogen/pull/7706) (**partially closed** --
  this fixes the same resolve-and-check-private-ranges half of that PR, but not its other half,
  the redirect-guard / `follow_redirects=False` revalidation, which is the still-open
  redirect-chain gap above) and
  [crewAIInc/crewai#6504](https://github.com/crewAIInc/crewai/issues/6504) (**partially closed, and
  only one of its two reported vulnerabilities** -- narrows vulnerability 1's DNS-rebinding TOCTOU
  window (catches the static case, not the actual rebinding race) and does not address vulnerability
  2 (MCP tool wrappers bypassing SSRF validation entirely) at all, which is an integration-
  completeness question, not a classifier-coverage gap).
- `toolgovern-cli` (0.1.5): `--json` flag on `validate`, `audit`, and `init` -- emits a single
  structured `{ ok, command, data | error }` JSON object on stdout instead of human-formatted
  text, so another program (an AI agent invoking the CLI programmatically, a script piping into
  `jq`) can parse the result reliably. Exit codes are unchanged (0 success, 1 runtime error, 2
  usage error) and were already non-zero on failure before this change; `--json` mode never
  splits output across stdout/stderr -- the full result, success or failure, is always the one
  JSON object on stdout. `audit --json` includes the full filtered `TraceEntry` objects, not a
  restated summary.

### Fixed

- `verifyChain()`'s signature comparison switched from `!==` (a naive string comparison) to
  `crypto.timingSafeEqual()`, guarded by a length check first (buffers of unequal length are
  rejected as non-matching without calling `timingSafeEqual`, which throws on unequal-length
  input -- the guard leaks nothing an attacker doesn't already know, since both signature
  schemes' lengths are fixed and public). Identified during a timing-analysis review as a real
  but low-severity gap: `verifyChain` runs against a local file in a single process, with no
  network round-trip or remote oracle for an attacker to time, so this was judged below the
  confidence gate for that threat model -- applied anyway as defense in depth, since the fix is
  free and the reasoning for skipping it stops applying the moment this logic is ever reused
  somewhere network-facing.
- `toolgovern-cli`'s `isMainModule` check compared `import.meta.url` directly against
  `pathToFileURL(process.argv[1])`, but npm installs a package's `bin` entry as a symlink --
  Node resolves `import.meta.url` to the symlink's realpath while leaving `process.argv[1]` as
  the symlink path itself, so the two never matched and `main()` silently never ran. Every real
  `npm install toolgovern-cli` (or `npx toolgovern-cli`) exited 0 with zero output, no usage
  text, no error. Fixed by resolving `process.argv[1]` through `realpathSync()` before the
  comparison. Verified against the exact real-world symlinked-bin path (packed the tarball,
  installed it fresh, ran the installed `node_modules/.bin/toolgovern-cli` directly), not just
  a source-level `node src/cli.ts` invocation, which had been masking this bug.
- `homepage` and `bugs` fields added to all 4 published package.json files (`toolgovern`,
  `toolgovern-cli`, `toolgovern-integration-langgraph`, `toolgovern-integration-oma`) -- none
  had them, so none of the 4 npm registry pages linked back to the repo or its issue tracker.
- Root README: two leftover "31-rule" mentions (comparison table, FAQ) corrected to the current,
  verified 34-rule count; GitHub About description corrected to match.
- Root README `## CLI` section: added a real `toolgovern-cli init langgraph` example with actual
  captured output -- the Framework Integration section referenced this command, but it had no
  usage example of its own.

### Added

- Root README: dedicated "API reference" section listing every real export from `toolgovern`'s
  entry point (middleware, scoping, trace, policy, classifier), grepped from source
- `toolgovern-cli` (0.1.3): added a `keywords` field to `package.json` -- the published npm listing
  had none, unlike the other three packages in this repo
- `toolgovern-integration-langgraph` (published, 0.1.0) -- new package routing LangGraph.js tool calls through `governTool()` before they reach `ToolNode`. LangGraph.js's `ToolNode` has no `wrap_tool_call` hook (that only exists in the Python `langgraph` package); the integration point is wrapping each tool with `governTool()` then re-wrapping it with LangChain's own `tool()` factory before it goes into `new ToolNode([...])`
- `toolgovern-integration-oma` published as an independent package (was previously an unpublished, `private: true` reference adapter in the repo only)
- `toolgovern-cli init [oma|langgraph]` -- scaffolds a real, working integration file wiring `governTool()`/`governedLangGraphTools()` into a project, auto-detected from `open-multi-agent`/`node_runner` or `@langchain/langgraph` in the invoking project's `package.json` (`toolgovern-cli` bumped to 0.1.2)
- Optional HMAC-keyed trace signing: `TraceWriterOptions.secretKey`, `verifyChain({ secretKey })`,
  and `toolgovern-cli audit --verify-chain --key-file <path>` -- makes the trace tamper-evident
  against an attacker who does not hold the key, not just against a naive hand-edit
- `TG01-decoded-payload-execution` rule -- catches base64/hex/openssl-decode-then-execute shell
  patterns that have no literal `curl`/`wget` token for `TG01-pipe-to-shell` to match
- `TG01-context-flood` rule -- flags read-only, high-output-volume commands (`ls -R` with no
  scoped path, `find` with no `-maxdepth` over an unscoped root, unscoped `grep -r`/`-R`, `cat`
  over a recursive globstar) that can flood an agent's context window even though nothing is
  destroyed or exfiltrated; decided as `require-approval`, not `deny`, since this is a cost/UX
  problem, not a security breach
- `docs/security-model.md` -- full threat-modeling writeup: what was found, what was fixed, what
  is a documented v0.1 limitation
- `benchmarks/README.md` -- real, measured detection-rate/false-positive-rate/latency numbers
- `docs/branch-protection.md` -- the exact commands to lock down `main` when the maintainers are
  ready to turn that on

### Changed

- Classifier text matching (TG01 shell rules, TG04 credential rules, TG03 host extraction) now
  runs through `normalizeForMatch()` first, closing confirmed bypasses via base64-decode piping,
  empty-quote-pair splitting (`r""m -rf /`), invisible Unicode characters, and `$IFS`-as-space
  substitution
- `TG01-rm-rf`'s regex rewritten to remove a confirmed polynomial-time ReDoS (6s on an
  80,000-character adversarial argument; now ~2.5ms)
- Benchmark corpus grown from 18 to 112 labeled cases, 15-29 per rule category, with a
  category-aware detection-rate calculation in `detection-rate.ts`

### Fixed

- Root README: rule count corrected from a stale "31" (comparison table, FAQ) to the actual current
  34, matching the rule-pack table and benchmarks section which already said 34
- Root README comparison table: swapped the NVIDIA column from NeMo Guardrails (LLM input/output
  content filtering -- not a tool-call gate, confirmed not genuinely comparable) to NeMo Relay
  (actual pre-tool-call interception via hooks), a more honest comparison
- `governTool()`: a throwing/rejecting `onApprovalRequired` handler now fails closed like a
  timeout, instead of skipping the trace write and leaking a raw, untyped error
- `toolgovern-cli audit --since <bad-value>` (e.g. an unsupported unit like `1s`) now returns a
  clean, code-2 error instead of crashing with a raw stack trace
- `verifyChain({ secretKey })` no longer applies the supplied key to `sha256:`-scheme entries --
  before this fix, passing `--key-file` against a trace that was never hmac-signed made every
  legitimate entry spuriously fail chain verification, found during manual end-to-end CLI testing

## [0.1.6] - 2026-07-16

### Added

- `toolgovern-cli`: `--json` flag on `validate`, `audit`, and `init` -- emits a single
  structured `{ ok, command, data | error }` JSON object on stdout instead of human-formatted
  text, so another program (an AI agent invoking the CLI programmatically, a script piping into
  `jq`) can parse the result reliably. Exit codes are unchanged (0 success, 1 runtime error, 2
  usage error); `--json` mode never splits output across stdout/stderr -- the full result,
  success or failure, is always the one JSON object on stdout. `audit --json` includes the full
  filtered `TraceEntry` objects, not a restated summary.
- README audit: documented `--json` in the `toolgovern-cli` package README, added a
  command/flag reference table and a `--json` section to the root README, refreshed
  comparison-table star counts against a live check, and added Contributing/FAQ coverage for
  the new agent-native output mode.

## [0.1.1] - 2026-07-12

### Added

- `packages/toolgovern/README.md` and `packages/toolgovern-cli/README.md` -- both published
  packages shipped with zero README content until this release (`npm view toolgovern readme`
  returned "No README data found!"); each package now has its own focused, fact-checked
  documentation, not just a copy of the monorepo root README
- `TG02-read-outside-scope` and `TG05-zero-capability-sub-agent` now have real corpus coverage in
  `benchmarks/corpus.ts` (they shipped with zero test cases) -- extending the corpus surfaced a
  real false-positive bug, fixed in the same pass (see Fixed, below)
- Root README comparison table: a verified comparison against Microsoft's Agent Governance
  Toolkit, NVIDIA NeMo Guardrails, and LangGraph's human-in-the-loop middleware, replacing the
  previous prose-only "how it differs" section
- CI, npm version, and license badges; a table of contents; an FAQ section in the root README
- `governedTool()` in `integrations/oma/` -- a per-tool, registration-time wrap matching OMA's own
  reference implementation (`node_runner`'s `wrapToolWithEvents()`), alongside the existing
  dispatcher-shaped `governedExecutor`

### Fixed

- `TG02-read-outside-scope` fired `require-approval` on a credential file read even when that
  exact credential was explicitly granted via `scope.credentials` -- it only checked
  `scope.filesystem`, duplicating a check `TG04`'s rules already performed correctly.
  `isCredentialGranted()` moved to the shared `util.ts` and is now checked by both categories, so
  an explicit credential grant is honored consistently regardless of which rule sees the call
  first
- Rule-count and benchmark numbers across the README, `benchmarks/README.md`, and
  `docs/policy-schema.md` were stale and mutually inconsistent (variously citing 31, 32, or the
  wrong per-category counts) after `TG02-read-outside-scope` and `TG05-zero-capability-sub-agent`
  shipped without a docs update -- corrected everywhere to the current, verified count (34 rules)
  and re-measured against the real, current codebase (116-case corpus, 100.0% detection, 0.0%
  false-positive rate)

## [0.1.0] - 2026-07-11

Initial v0.1 build.

### Added

- `packages/toolgovern`: the `governTool()` middleware -- wraps any tool definition and evaluates
  every call through the classifier before it executes, returning allow / deny / require-approval
- Risk classifier with 5 rule categories (TG01-TG05), 30 rules total:
  - TG01 Shell/Process Execution Risk (7 rules)
  - TG02 Filesystem Scope Escalation (6 rules)
  - TG03 Undeclared Network Egress (6 rules)
  - TG04 Credential/Secret Access (6 rules)
  - TG05 Cross-Agent Privilege Inheritance (5 rules)
- Per-agent scope declaration and default-deny inheritance enforcement (`ScopeRegistry`,
  `computeInheritedScope`) -- a sub-agent's granted scope is the intersection of what it requests
  and what its coordinator actually has, re-checked on every call, not just at spawn time
- Signed, append-only JSON Lines trace (`TraceWriter`, `readTrace`, `filterTrace`, `verifyChain`)
  -- each entry's `signature` is a sha256 content hash, chained to the previous entry in the same
  session via `prior_trace_id`
- Policy file loader (`loadPolicy`) and validator (`validatePolicy`) for
  `toolgovern.policy.yml`, including rule-reference validation against the real rule ID registry
- `packages/toolgovern-cli`: `toolgovern-cli validate <policy-file>` and
  `toolgovern-cli audit <trace-file> [--since] [--decision] [--agent] [--rule] [--verify-chain]`
- `integrations/oma`: a generic, documented adapter shape (`governedExecutor`) for wiring
  toolgovern into a multi-agent framework's tool-executor call site -- not a submitted or merged
  upstream integration
- CI workflow: lint -> typecheck -> build -> test with coverage -> `npm audit --audit-level=high`
