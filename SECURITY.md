# Security Policy

toolgovern is a runtime governance/security tool. Vulnerabilities in it directly undermine the
guarantees it is meant to provide, so we treat reports seriously and ask that you report privately
first.

## Reporting a vulnerability

Please do **not** open a public GitHub issue for a suspected vulnerability.

Instead, open a [private security advisory](https://github.com/RudrenduPaul/toolgovern/security/advisories/new)
on this repository. Include:

- A description of the issue and its potential impact
- Steps to reproduce, or a minimal proof-of-concept tool call / policy file
- The affected version(s) or commit

We will acknowledge a report within 5 business days and aim to provide an initial assessment
(confirmed, not a vulnerability, or needs more information) within 10 business days.

## Scope

In scope:

- The classifier (`packages/toolgovern/src/classifier/`) -- any input that should be denied or
  require approval but is instead allowed
- The scoping registry (`packages/toolgovern/src/scoping/`) -- any way a sub-agent can exceed the
  scope its coordinator actually granted it
- The trace writer/reader (`packages/toolgovern/src/trace/`) -- any way a trace entry's content
  can be altered without `verifyChain()` detecting it
- `toolgovern-cli` -- any way `validate` or `audit` can be tricked into reporting an incorrect
  result

Out of scope for v0.1 (documented, not hidden):

- TG06 (high-risk tool combination) and TG07 (repeated-denial/anomalous retry) are not shipped
  yet -- they need cross-call session state the current stateless classifier does not model. A
  report that one of these detection classes is missing is a known gap, not a new finding.
- A gate result of `allow` is not a claim that the call is safe -- it means the call was checked
  against the current, finite rule set. A rule pack that is incomplete is an expected v0.1
  limitation; a rule that silently fails to run at all is a bug and in scope.

## Disclosure

We ask for a reasonable window to investigate and, where applicable, ship a fix before any public
disclosure. We will credit reporters (unless you prefer to stay anonymous) in the fix's changelog
entry.
