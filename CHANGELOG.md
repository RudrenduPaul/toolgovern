# Changelog

All notable changes to this project are documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- Optional HMAC-keyed trace signing: `TraceWriterOptions.secretKey`, `verifyChain({ secretKey })`,
  and `toolgovern-cli audit --verify-chain --key-file <path>` -- makes the trace tamper-evident
  against an attacker who does not hold the key, not just against a naive hand-edit
- `TG01-decoded-payload-execution` rule -- catches base64/hex/openssl-decode-then-execute shell
  patterns that have no literal `curl`/`wget` token for `TG01-pipe-to-shell` to match
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

- `governTool()`: a throwing/rejecting `onApprovalRequired` handler now fails closed like a
  timeout, instead of skipping the trace write and leaking a raw, untyped error
- `toolgovern-cli audit --since <bad-value>` (e.g. an unsupported unit like `1s`) now returns a
  clean, code-2 error instead of crashing with a raw stack trace
- `verifyChain({ secretKey })` no longer applies the supplied key to `sha256:`-scheme entries --
  before this fix, passing `--key-file` against a trace that was never hmac-signed made every
  legitimate entry spuriously fail chain verification, found during manual end-to-end CLI testing

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
