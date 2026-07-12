# CLAUDE.md -- toolgovern

## Project Identity

- **Idea:** Framework-agnostic runtime governance layer for AI agent tool calls -- an
  onToolCall risk-gating middleware, per-agent credential/tool/memory scoping, and a
  signed local audit trace, shipped free/OSS, plus a paid hosted layer (policy-management
  UI, cross-framework compatibility packs, compliance/audit reporting, fleet-wide
  enforcement gate)
- **Repo:** toolgovern-ai/toolgovern
- **npm packages:** toolgovern (middleware library), toolgovern-cli (audit/validate CLI)
- **Language:** TypeScript/Node (primary)
- **License:** Apache 2.0 (core middleware, classifier, scoping, local trace) + proprietary
  (hosted policy UI + compliance layer)
- **Repo goal:** Become the default onToolCall governance primitive multi-agent frameworks
  integrate directly, starting with a merged flagship PR against the exemplar framework.
  Stars and a merged upstream PR prove technical credibility and distribution.

## Git Workflow

When asked to commit, push, or "update GitHub" -- just do it. No questions.

- `git add` relevant files -> `git commit` -> `git push origin main` in one shot
- Every commit message ends with:
  Built by Rudrendu Paul and Sourav Nandy, developed with Claude Code
- Never use `Co-Authored-By:` lines.

## Engineering Standards (block all tasks until these pass)

1. **Lint:** `npx eslint . && npx prettier --check .`
2. **Types:** `npx tsc --noEmit --strict` -- zero errors, zero `@ts-ignore`/`@ts-expect-error` without a comment explaining why
3. **Tests:** `npx vitest run --coverage --coverage.lines=80` -- 80% minimum; 90%+ on the classifier and scoping-enforcement paths
4. **Security:** `npx trivy fs .` (or `npm audit --audit-level=high`) -- no HIGH or CRITICAL unfixed CVEs in the dependency tree
5. **Latency:** if you changed the classifier or the `onToolCall` hot path, run `benchmarks/latency.ts` and include the before/after per-call latency delta in your response -- this middleware runs inline on every tool call, so a regression here is a correctness-adjacent regression, not a nice-to-have

Do NOT mark a task complete if any of these fail. Fix the root cause. Do not suppress errors or add `@ts-ignore` patches.

## Planning Rules

Enter plan mode for any task that:

- Touches more than 2 files
- Changes the `onToolCall` hook interface or the policy-file schema
- Adds a new rule category (TG0x)
- Modifies the scoping-inheritance model

Write the plan before touching code. If something goes wrong mid-task, stop and re-plan.

## Anti-Sycophancy Rules

These override default behavior in every session:

1. **No detection-rate, false-positive-rate, or latency claim without a benchmark run.** Before stating any of these numbers, run the benchmark suite against the labeled corpus of real + synthetic risky/benign tool-call sequences and show the command output. Never state a number without showing the command that produced it.
2. **Every gate decision must be explainable from the trace alone.** A `deny` or `require-approval` decision that cannot be traced back to a specific rule ID and the exact argument that tripped it is a bug, not an acceptable black box -- security reviewers have to be able to answer "why was this blocked" from the JSON Lines trace without asking the maintainers.
3. **Comparison claims require specificity.** Any comparison to another runtime-governance tool or a framework's own native hook must specify exactly what toolgovern does differently (OSS-native, embedded via a direct wrapping call rather than a separate hosted control plane, in-process with no network round-trip). "We do governance" is not enough.
4. **Platform/security-engineer skepticism check.** Before merging any new rule or scoping change, ask: "would a platform-security engineer running agents in production consider this real enforcement, or theater that's easy to bypass by rephrasing the call?" If the honest answer is "theater," do not merge.
5. **Never claim "governed" implies "safe."** A gated call means it was evaluated against the current rule set, not that it is guaranteed harmless. The rule set is finite and TG06/TG07 are not yet shipped in v0.1 -- state that limitation plainly wherever the gate result is surfaced.

## What Claude Must Never Do

- Claim a detection, false-positive, or latency number without a benchmark command output
- Ship a new rule category without a labeled test case proving true-positive and true-negative behavior
- Commit with `--no-verify`
- Merge a PR that regresses classifier latency or detection rate without explicit written approval
- State that a gated agent session is "safe" or "secure" -- the trace records what was evaluated and decided, never an absolute safety guarantee

## Key Files

| File                                               | Purpose                                                                                                                                 |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/toolgovern/src/middleware/onToolCall.ts` | The core hook -- wraps a tool definition, evaluates the classifier, returns allow/deny/require-approval                                 |
| `packages/toolgovern/src/classifier/`              | Rule packs -- one per category: shell-risk, filesystem-scope, network-egress, credential-access, cross-agent-inheritance                |
| `packages/toolgovern/src/scoping/`                 | Per-agent scope declaration, default-deny inheritance enforcement                                                                       |
| `packages/toolgovern/src/trace/`                   | Signed, append-only JSON Lines trace writer and reader                                                                                  |
| `packages/toolgovern-cli/src/cli.ts`               | `toolgovern-cli validate`, `toolgovern-cli audit` entry points                                                                          |
| `integrations/oma/`                                | A generic, documented adapter shape for a multi-agent framework's tool-executor call site (not a submitted/merged upstream integration) |
| `benchmarks/`                                      | Detection-rate and per-call latency benchmarks against a labeled corpus -- reproducible                                                 |
| `CONTRIBUTING.md`                                  | Read before any contributor-facing change                                                                                               |
| `SECURITY.md`                                      | CVE disclosure policy                                                                                                                   |
| `CHANGELOG.md`                                     | Updated on every PR that changes public behavior                                                                                        |
| `.github/workflows/ci.yml`                         | lint -> type-check -> build -> test -> security                                                                                         |

## Session Start Checklist

1. Run `git status` and `git log --oneline -5` to understand current state
2. Run `npx vitest run` to confirm baseline is green before touching anything
3. Read `CHANGELOG.md` last entry to understand what changed recently
4. If a bug is reported: write a failing test case (a labeled risky or benign tool-call sequence) that reproduces it first, then fix it
5. Check whether the classifier rule pack, scoping model, or trace schema described above still matches what's actually in `src/` before making claims about behavior
