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
  "agent_id_source": "explicit",
  "signature": "sha256:d8f21b...",
  "prior_trace_id": "tg_2026-07-11_a91f02"
}
```

A call that went through human approval carries one more field, `approved_by`, naming who resolved
it:

```json
{
  "trace_id": "tg_2026-07-11_9b3f0d",
  "timestamp": "2026-07-11T09:15:03.000Z",
  "session_id": "multi-agent-run-8f2c",
  "agent_id": "research-sub",
  "tool": "http_fetch",
  "arguments_hash": "sha256:1e9a44...",
  "decision": "allow",
  "rule_fired": ["TG03-host-not-in-scope"],
  "declared_scope": { "network": false, "filesystem": ["./workspace"], "credentials": [] },
  "signature": "sha256:7c02f1...",
  "prior_trace_id": "tg_2026-07-11_c4e9a1",
  "approved_by": "jane@example.com"
}
```

## Fields

| Field             | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `trace_id`        | Derived from a sha256 hash of the entry's own content, prefixed with the date                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `timestamp`       | ISO 8601 UTC timestamp of the gate decision                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `session_id`      | The session this call belongs to -- chains only link within one session                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `agent_id`        | The calling agent's identity                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `tool`            | The tool name that was called                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `arguments_hash`  | `sha256:<hex>` of the call's arguments -- the raw arguments themselves are not stored, only their hash                                                                                                                                                                                                                                                                                                                                                                                                       |
| `decision`        | `"allow"`, `"deny"`, or `"require-approval"`                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `rule_fired`      | Rule IDs that fired for this call. Empty for a clean `allow`. If empty and the decision is not `allow`, the entry records `["policy-default-decision"]`, meaning a policy's `defaultDecision` setting -- not a classifier rule -- produced the decision.                                                                                                                                                                                                                                                     |
| `declared_scope`  | The agent's effective scope at the time of the call                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `agent_id_source` | `"explicit"` if the caller passed `agentId` to `governTool()`, `"fallback"` if none was supplied and toolgovern used its default (`'default-agent'`). Optional -- absent on entries written directly via `TraceWriter.append()` without a source, and on traces written before this field existed. This is provenance only, **not** proof: an `"explicit"` value just means a caller supplied _some_ string, not that the string is true. See "What `agent_id`/`agent_id_source` do and do not prove" below. |
| `signature`       | `sha256:<hex>` by default, or `hmac-sha256:<hex>` if `TraceWriter` was given a `secretKey`. Recomputing it and comparing (`verifyChain()`) detects any change to the entry after it was written.                                                                                                                                                                                                                                                                                                             |
| `prior_trace_id`  | The `trace_id` of the previous entry in the same session, or `null` for the first entry in a session                                                                                                                                                                                                                                                                                                                                                                                                         |
| `approved_by`     | Identity of the human who resolved a `require-approval` gate -- whether resolved synchronously via `onApprovalRequired` or out-of-band via `PendingApprovalRegistry.resolvePending()`. Absent for calls that never went through human approval.                                                                                                                                                                                                                                                            |

## What "signed" means here

By default, `signature` is a `sha256:` content hash, not a keyed signature -- there is no key to
manage. It proves an entry has not been altered since `TraceWriter` wrote it (or that it has, if
recomputing the hash produces a different value) and, combined with `prior_trace_id`, that entries
have not been reordered or had one silently deleted from the middle of a session.

That default is enough to catch accidental corruption or a naive hand-edit, but it does **not**
stop a determined attacker: because the hash requires no secret to reproduce, anyone with write
access to the trace file can edit an entry and recompute a `signature` that still passes
`verifyChain()`. This is disclosed, not hidden -- `packages/toolgovern/test/trace/trace-reader.test.ts`
has a test that demonstrates it directly, and `docs/security-model.md` covers it under "known
limitations."

Pass a `secretKey` to `TraceWriter` (see `TraceWriterOptions`) to sign with `hmac-sha256:`
instead. An attacker who does not also hold that key cannot produce a signature that verifies,
which is what actually makes the trace tamper-evident rather than just tamper-evident-against-
naive-edits. toolgovern does not generate, store, or rotate this key for you -- pass the same key
to `verifyChain()` (or `toolgovern-cli audit --verify-chain --key-file <path>`) to check it. Even
keyed, an attacker who can read both the trace file and the key file (e.g. the same OS user the
agent runs as) can still forge a valid trace -- v0.1 has no external anchor or key-management
service. `verifyChain()` is a tamper-evidence check, not a tamper-_proof_ guarantee, keyed or not.

## What `agent_id`/`agent_id_source` do and do not prove

`agent_id` is a caller-supplied string. toolgovern validates its _format_ (`isValidAgentId()` in
`packages/toolgovern/src/scoping/scope-declaration.ts` rejects empty strings, strings over 256
characters, and strings containing control characters or embedded null bytes -- the kinds of
input that indicate a malformed or injection-style payload rather than a real identity) and
records `agent_id_source` so a reader knows whether the value came from an explicit
`options.agentId` or the `'default-agent'` fallback. Neither of these is cryptographic identity
verification. Passing format validation only means the string is _well-formed_ -- it does not
mean the caller who supplied it is actually who they claim to be. Any caller that knows the
`governTool()` API can still assert any well-formed `agentId` string, explicit or not, and have
it accepted. Full cryptographic identity verification (e.g., signed caller tokens, mTLS client
identity, a trusted broker that mints `agentId`s) is out of scope for v0.1 -- see
`docs/security-model.md`.

## Reading a trace

```bash
npx toolgovern-cli audit ./toolgovern-trace.jsonl --since 24h --decision deny

# verifying a trace written with a secret key
npx toolgovern-cli audit ./toolgovern-trace.jsonl --verify-chain --key-file ./trace-key.bin
```

Programmatically:

```ts
import { readTrace, filterTrace, verifyChain } from 'toolgovern';

const entries = await readTrace('./toolgovern-trace.jsonl');
const denies = filterTrace(entries, { decision: 'deny' });
const { valid, issues } = verifyChain(entries);
// or, for an hmac-signed trace:
// const { valid, issues } = verifyChain(entries, { secretKey: myKeyBuffer });
```
