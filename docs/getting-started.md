# Getting started

toolgovern ships two independent, equally first-class packages: the original `toolgovern` /
`toolgovern-cli` npm packages, and a genuine Python port (`toolgovern` on PyPI, console script
`toolgovern-cli`). Both read the same rule IDs, apply the same default-deny scope model, and
write trace entries in the same JSON Lines shape -- pick whichever fits your agent runtime.

## Install

```bash
# npm -- JavaScript/TypeScript core library + CLI
npm install toolgovern
npm install --save-dev toolgovern-cli

# PyPI -- Python core library + CLI (genuine port, not a wrapper around the Node binary)
pip install toolgovern
```

The Python package's console script is `toolgovern-cli`, matching the npm CLI's command name.

## Your first policy and gate

Create a policy file:

```yaml
# toolgovern.policy.yml
name: strict-shell
scope:
  network: false
  filesystem:
    - ./workspace
  credentials: []
defaultDecision: allow
```

Validate it:

```bash
# TypeScript
npx toolgovern-cli validate ./toolgovern.policy.yml

# Python
toolgovern-cli validate ./toolgovern.policy.yml
```

Both print `OK  ./toolgovern.policy.yml is a valid toolgovern policy.` and exit `0`.

Wrap a tool so every call is evaluated before it executes:

```python
from toolgovern import ToolDefinition, GovernToolOptions, govern_tool, load_policy, ToolGovernDenialError

policy = load_policy("./toolgovern.policy.yml")

def run_shell(args):
    import subprocess
    return subprocess.run(args["command"], shell=True, capture_output=True, text=True)

shell_tool = ToolDefinition(name="shell", execute=run_shell)
gated_shell = govern_tool(shell_tool, GovernToolOptions.from_policy(policy))

try:
    gated_shell.execute({"command": "rm -rf /"})
except ToolGovernDenialError as e:
    print(e)  # denied before subprocess.run ever runs
```

```typescript
// The equivalent TypeScript call site
import { governTool, loadPolicy, ToolGovernDenialError } from 'toolgovern';

const policy = loadPolicy('./toolgovern.policy.yml');
const gatedShell = governTool(shellTool, policy);

try {
  await gatedShell.execute({ command: 'rm -rf /' });
} catch (e) {
  if (e instanceof ToolGovernDenialError) console.log(e.message);
}
```

`rm -rf /` never reaches your shell implementation in either language -- the classifier denies
it before `execute()` runs, and (if a `trace` is wired in) the denial is written to the audit
trail with the rule ID that fired (`TG01-rm-rf`).

## Auditing a trace

```bash
# TypeScript
npx toolgovern-cli audit ./toolgovern-trace.jsonl --since 24h --decision deny --verify-chain

# Python
toolgovern-cli audit ./toolgovern-trace.jsonl --since 24h --decision deny --verify-chain
```

`--verify-chain` recomputes every entry's signature and confirms the `prior_trace_id` chain is
intact -- it reports every issue found, not just the first, and exits non-zero if anything
doesn't verify.

## Next steps

- [Concepts](./concepts.md) -- the classifier, scope inheritance, and the signed trace model
- [CI integration](./integrations/ci.md) -- wiring `validate`/`audit` into a pipeline
- [docs/security-model.md](./security-model.md) -- the real threat model, what's fixed, what's a
  disclosed v0.1 limitation
- [docs/trace-format.md](./trace-format.md) -- the exact trace entry schema
- [docs/policy-schema.md](./policy-schema.md) -- the full policy file field reference
- [CHANGELOG.md](../CHANGELOG.md) -- version history for both distributions
