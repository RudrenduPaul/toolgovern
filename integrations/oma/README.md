# toolgovern-integration-oma

[![npm version](https://img.shields.io/npm/v/toolgovern-integration-oma.svg)](https://www.npmjs.com/package/toolgovern-integration-oma)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/RudrenduPaul/toolgovern/blob/main/LICENSE)

Adapter shapes for wiring [toolgovern](https://www.npmjs.com/package/toolgovern) into an
open-multi-agent-style framework's tool-executor call site -- gate shell, filesystem, network, and
credential access before a tool runs.

```bash
npm install toolgovern-integration-oma toolgovern
```

This is a generic, documented reference adapter, not a submitted or merged integration against any
specific upstream project. It's a working starting point to adapt, not a claim that any framework
ships this today.

## Two shapes

Two patterns are provided, matching the two real integration shapes multi-agent frameworks
actually use. Start with `governedTool()` unless the framework you're integrating genuinely has a
single dispatcher.

### `governedTool(tool, options)` -- per-tool, registration-time wrapping

This is the pattern [open-multi-agent](https://github.com/open-multi-agent/open-multi-agent)'s own
reference implementation (`node_runner`'s `wrapToolWithEvents()`) actually uses: wrap one
`{name, execute}` tool at the point it's registered, before it's added to a tool registry.

```ts
import { governedTool } from 'toolgovern-integration-oma';
import { loadPolicy } from 'toolgovern';

const policy = loadPolicy('./toolgovern.policy.yml');
registry.register(governedTool(myTool, policy));
```

### `governedExecutor(baseExecutor, options)` -- dispatcher wrapping

For frameworks whose tool-executor layer is a single `runTool(name, args)` dispatch point rather
than per-tool registration.

```ts
import { governedExecutor } from 'toolgovern-integration-oma';
import { loadPolicy } from 'toolgovern';

const policy = loadPolicy('./toolgovern.policy.yml');
const executor = governedExecutor(baseExecutor, policy);

// wherever the framework currently calls baseExecutor.runTool(name, args) directly,
// call executor.runTool(name, args) instead -- every call now flows through the
// classifier first.
```

`ToolExecutorLike`'s method and field names are illustrative, not a claim about any specific
framework's actual API -- adjust it to match the real interface you are integrating against.

See the [full toolgovern documentation](https://github.com/RudrenduPaul/toolgovern) on GitHub for
the middleware itself, the rule pack, and the trace format spec.

## License

Apache 2.0. See [LICENSE](https://github.com/RudrenduPaul/toolgovern/blob/main/LICENSE).
