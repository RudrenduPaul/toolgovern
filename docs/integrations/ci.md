# CI integrations

## Validate a policy file on every push (either distribution)

```yaml
# .github/workflows/toolgovern-policy.yml
name: toolgovern policy check
on: [push, pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # npm CLI
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npx toolgovern-cli validate ./toolgovern.policy.yml

      # -- or --

      # Python CLI
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install toolgovern
      - run: toolgovern-cli validate ./toolgovern.policy.yml
```

Either CLI exits non-zero on an invalid policy, which fails the job. Add `--json` to either
command to get a structured `{ ok, command, data | error }` object on stdout instead of the
human-formatted text, if a later step needs to parse the result.

## Verify an audit trail's integrity in CI

If your agent runtime writes a `toolgovern-trace.jsonl` during a CI run (e.g. an integration
test that exercises real tool calls through a governed agent), verify the chain before the job
finishes so a broken or tampered trace fails the build rather than being silently accepted:

```bash
toolgovern-cli audit ./toolgovern-trace.jsonl --verify-chain --decision deny
```

`--verify-chain` exits non-zero and prints every issue found if any entry's signature doesn't
match its content or the `prior_trace_id` chain is broken. Pass `--key-file <path>` if the trace
was written with an HMAC-keyed `TraceWriter` (`secretKey`/`secret_key`) -- entries signed with
the default unkeyed `sha256:` scheme verify without it.

## Pre-commit hook (Python)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: toolgovern-validate
        name: toolgovern policy validate
        entry: toolgovern-cli validate toolgovern.policy.yml
        language: system
        pass_filenames: false
```

## Choosing a severity response

`toolgovern-cli validate` and `audit --verify-chain` are pass/fail (exit `0` vs non-zero) --
there is no severity threshold to tune, unlike a scanner that reports findings across multiple
severity levels. A policy either parses and references only real rule IDs, or it doesn't; a
trace chain either verifies, or it doesn't. Gate the CI job on the exit code directly.
