# Policy file schema

`loadPolicy()` reads a YAML file matching this shape:

```yaml
# toolgovern.policy.yml
name: strict-shell # optional, free-form label
policy: strict-shell # optional, free-form label (alias -- either or both may be set)

scope:
  network: false # false | true | ["host.example.com", ...]
  filesystem:
    - ./workspace
  credentials: []

# optional: decision to use when no classifier rule fires at all. Defaults to "allow".
defaultDecision: allow

# optional: per-rule overrides
rules:
  disable: [] # rule IDs to skip entirely, e.g. ["TG01-sudo"]
  requireApproval: [] # rule IDs whose default "deny" should downgrade to "require-approval"
```

## Fields

| Field                   | Type                                      | Required | Notes                                                                                                                    |
| ----------------------- | ----------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------ |
| `name`                  | string                                    | no       | Declared policy name, surfaced in trace/UX contexts                                                                      |
| `policy`                | string                                    | no       | Free-form label, e.g. `"strict-shell"` -- not used for rule matching                                                     |
| `scope.network`         | `false \| true \| string[]`               | yes      | `false` = no network access, `true` = unrestricted, array = hostname allowlist (subdomains of an allowed host match too) |
| `scope.filesystem`      | `string[]`                                | yes      | Path prefixes the agent may read/write/delete under                                                                      |
| `scope.credentials`     | `string[]`                                | yes      | Credential identifiers (file paths, secret names) the agent may access                                                   |
| `defaultDecision`       | `"allow" \| "deny" \| "require-approval"` | no       | Applied only when no rule fires at all. Defaults to `"allow"`.                                                           |
| `rules.disable`         | `string[]`                                | no       | Rule IDs to skip entirely, regardless of arguments                                                                       |
| `rules.requireApproval` | `string[]`                                | no       | Rule IDs whose `deny` verdict downgrades to `require-approval`                                                           |

`loadPolicy()` validates the file and throws `PolicyValidationError` (with every error found, not
just the first) if it is structurally invalid or references an unknown rule ID in
`rules.disable`/`rules.requireApproval`. Run `toolgovern-cli validate <policy-file>` to check a
policy file without loading it into a program.

## Rule IDs

See `packages/toolgovern/src/classifier/index.ts`'s `ruleRegistry` for the authoritative list.
As of v0.1: `TG01-*` (8 rules), `TG02-*` (6 rules), `TG03-*` (6 rules), `TG04-*` (6 rules),
`TG05-*` (5 rules) -- 31 rules total. Each rule file documents its own rules with a description
comment.
