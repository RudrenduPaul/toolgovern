# Changelog

All notable changes to this project are documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

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
