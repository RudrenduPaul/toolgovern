# Trace format

Every gate decision -- `allow`, `deny`, or `require-approval` -- is written as one line of a
JSON Lines (`.jsonl`) file by `TraceWriter`. Each line is a self-contained JSON object:

```json
{
  "trace_id": "tg_2026-07-11_c4e9a1",
  "timestamp": "2026-07-11T09:14:52.000Z",
  "session_id": "multi-agent-run-8f2c",
  "agent_id": "research-sub",
  "tool": "bash",
  "arguments_hash": "sha256:af31c2...",
  "decision": "deny",
  "rule_fired": ["TG01-pipe-to-shell"],
  "declared_scope": { "network": false, "filesystem": ["./workspace"], "credentials": [] },
  "signature": "sha256:d8f21b...",
  "prior_trace_id": "tg_2026-07-11_a91f02"
}
```

## Fields

| Field            | Meaning                                                                                                                                                                                                                                                  |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `trace_id`       | Derived from a sha256 hash of the entry's own content, prefixed with the date                                                                                                                                                                            |
| `timestamp`      | ISO 8601 UTC timestamp of the gate decision                                                                                                                                                                                                              |
| `session_id`     | The session this call belongs to -- chains only link within one session                                                                                                                                                                                  |
| `agent_id`       | The calling agent's identity                                                                                                                                                                                                                             |
| `tool`           | The tool name that was called                                                                                                                                                                                                                            |
| `arguments_hash` | `sha256:<hex>` of the call's arguments -- the raw arguments themselves are not stored, only their hash                                                                                                                                                   |
| `decision`       | `"allow"`, `"deny"`, or `"require-approval"`                                                                                                                                                                                                             |
| `rule_fired`     | Rule IDs that fired for this call. Empty for a clean `allow`. If empty and the decision is not `allow`, the entry records `["policy-default-decision"]`, meaning a policy's `defaultDecision` setting -- not a classifier rule -- produced the decision. |
| `declared_scope` | The agent's effective scope at the time of the call                                                                                                                                                                                                      |
| `signature`      | `sha256:<hex>` -- a content hash of every other field in the entry. Recomputing it and comparing (`verifyChain()`) detects any change to the entry after it was written.                                                                                 |
| `prior_trace_id` | The `trace_id` of the previous entry in the same session, or `null` for the first entry in a session                                                                                                                                                     |

## What "signed" means here

`signature` is a sha256 content hash, not a PKI signature -- there is no private signing key to
manage. It proves an entry has not been altered since `TraceWriter` wrote it (or that it has, if
recomputing the hash produces a different value) and, combined with `prior_trace_id`, that entries
have not been reordered or had one silently deleted from the middle of a session. This is
sufficient for a local, self-hosted trace file reviewed by the team that generated it. It does not
prove who wrote a given entry (that would require an actual signing key), and it does not detect
an attacker who has full write access to the trace file recomputing every subsequent hash after
tampering with an early entry -- `verifyChain()` is a tamper-evidence check, not a
tamper-_proof_ guarantee.

## Reading a trace

```bash
npx toolgovern-cli audit ./toolgovern-trace.jsonl --since 24h --decision deny
```

Programmatically:

```ts
import { readTrace, filterTrace, verifyChain } from 'toolgovern';

const entries = await readTrace('./toolgovern-trace.jsonl');
const denies = filterTrace(entries, { decision: 'deny' });
const { valid, issues } = verifyChain(entries);
```
