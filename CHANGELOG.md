# Changelog

All notable changes to this project are documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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
