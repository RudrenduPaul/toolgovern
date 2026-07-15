# toolgovern-cli

[![npm version](https://img.shields.io/npm/v/toolgovern-cli.svg)](https://www.npmjs.com/package/toolgovern-cli)
[![CI](https://github.com/RudrenduPaul/toolgovern/actions/workflows/ci.yml/badge.svg)](https://github.com/RudrenduPaul/toolgovern/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/RudrenduPaul/toolgovern/blob/main/LICENSE)

Validate [toolgovern](https://www.npmjs.com/package/toolgovern) policy files, audit local gate
traces, and scaffold framework integration boilerplate -- all from the command line, without
needing a hosted dashboard. Every command also takes `--json` for structured output an AI agent or
script can parse directly, instead of scraping text.

```bash
npx toolgovern-cli validate ./toolgovern.policy.yml
npx toolgovern-cli audit ./toolgovern-trace.jsonl --since 24h --decision deny
npx toolgovern-cli init langgraph
npx toolgovern-cli audit ./toolgovern-trace.jsonl --decision deny --json
```

## Commands

### `validate <policy-file> [--json]`

Checks a `toolgovern.policy.yml` file's structure and rule references before it loads at runtime.

```
$ toolgovern-cli validate ./toolgovern.policy.example.yml
OK  ./toolgovern.policy.example.yml is a valid toolgovern policy.
```

### `audit <trace-file> [flags]`

Reads a local trace file written by `toolgovern`'s `TraceWriter` and filters it.

```
$ toolgovern-cli audit ./toolgovern-trace.jsonl --decision deny
DENY             research-sub -> bash  [TG01-pipe-to-shell, TG03-network-disabled, TG03-known-paste-relay]  2026-07-12T01:39:22.581Z

1 of 2 trace entries matched.
```

| Flag                                         | What it does                                                                                                                                                    |
| -------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--since <window>`                           | Only entries within the window, e.g. `24h`, `7d`                                                                                                                |
| `--decision <allow\|deny\|require-approval>` | Filter by gate decision                                                                                                                                         |
| `--agent <id>`                               | Filter by agent identity                                                                                                                                        |
| `--rule <ruleId>`                            | Filter by which rule fired                                                                                                                                      |
| `--verify-chain`                             | Recompute every entry's signature and confirm the `prior_trace_id` chain is intact -- add `--key-file <path>` if the trace was written with an HMAC `secretKey` |
| `--json`                                     | Structured output instead of the text table above -- see [`--json`](#--json----structured-output-for-scripts-and-agents) below                                  |

### `init [oma|langgraph] [flags]`

Scaffolds a real, working integration file wiring `governTool()` into your project -- not a stub
comment, actual generated code you fill in a tool list and policy path for and run.

With no framework named, it looks at the current directory's `package.json` and detects which
integration applies: `open-multi-agent`/`node_runner` dependencies scaffold the `oma` adapter,
`@langchain/langgraph` scaffolds the `langgraph` adapter. Pass the framework explicitly to skip
detection.

```
$ toolgovern-cli init langgraph
Scaffolded langgraph integration at toolgovern.langgraph.ts.
Fill in your real tool(s) and confirm the policy path (./toolgovern.policy.yml) before running.
```

| Flag              | What it does                                                                                                                   |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `--policy <path>` | Policy file path baked into the generated `loadPolicy()` call. Defaults to `./toolgovern.policy.yml`                           |
| `--out <path>`    | Where to write the scaffold file. Defaults to `toolgovern.oma.ts` or `toolgovern.langgraph.ts`                                 |
| `--force`         | Overwrite an existing file at `--out`                                                                                          |
| `--json`          | Structured output instead of the text lines above -- see [`--json`](#--json----structured-output-for-scripts-and-agents) below |

## `--json` -- structured output for scripts and agents

Every command above accepts `--json`. Instead of the human-formatted text shown in the examples,
it prints exactly one JSON object to stdout and nothing to stderr, whether the command succeeds or
fails -- the exit code (0 success, 1 runtime error, 2 usage error, the same codes as text mode)
tells you which, and the object's `ok` field mirrors that. This is the shape an AI agent or script
invoking this CLI programmatically should parse, instead of scraping the text output:

```
$ toolgovern-cli validate ./toolgovern.policy.example.yml --json
{
  "ok": true,
  "command": "validate",
  "data": { "file": "./toolgovern.policy.example.yml", "valid": true, "errors": [] }
}

$ toolgovern-cli audit ./toolgovern-trace.jsonl --decision deny --json
{
  "ok": true,
  "command": "audit",
  "data": {
    "file": "./toolgovern-trace.jsonl",
    "query": { "decision": "deny" },
    "matched": 1,
    "total": 2,
    "entries": [ { "trace_id": "...", "decision": "deny", "rule_fired": ["TG01-pipe-to-shell"] } ]
  }
}

$ toolgovern-cli validate ./does-not-exist.yml --json
{
  "ok": false,
  "command": "validate",
  "error": { "message": "Failed to read/parse \"./does-not-exist.yml\": ENOENT: no such file or directory, open './does-not-exist.yml'" }
}
```

`audit --json`'s `entries` array holds the real `TraceEntry` objects with every field intact, so a
downstream agent can act on `decision`, `rule_fired`, `agent_id`, and the rest directly. A
structural `validate` failure (a policy file that parses but fails rule checks) still returns
`ok: false` and exit code 1, but also includes `data.errors` (the same list as `error.details`), so
a caller can see exactly which checks failed and why.

## Why a CLI, not just a library

`toolgovern`'s `TraceWriter` produces a plain, append-only JSON Lines file on your own machine --
no server, no account. `toolgovern-cli` is the read side of that: a way to actually look at what
your agents did without writing a parser yourself, and a way to check `--verify-chain` proves the
trace hasn't been quietly edited after the fact. `init` is the write side of getting started: a
real wiring file instead of copy-pasting a README snippet.

See the [full toolgovern documentation](https://github.com/RudrenduPaul/toolgovern) on GitHub for
the middleware itself, the rule pack, and the trace format spec.

## License

Apache 2.0. See [LICENSE](https://github.com/RudrenduPaul/toolgovern/blob/main/LICENSE).
