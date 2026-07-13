# toolgovern-integration-langgraph

[![npm version](https://img.shields.io/npm/v/toolgovern-integration-langgraph.svg)](https://www.npmjs.com/package/toolgovern-integration-langgraph)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/RudrenduPaul/toolgovern/blob/main/LICENSE)

Route [LangGraph.js](https://github.com/langchain-ai/langgraphjs) tool calls through
[toolgovern](https://www.npmjs.com/package/toolgovern)'s `governTool()` gate before they reach
`ToolNode` -- shell, filesystem, network, and credential access evaluated (allow, deny, or
require-approval) before your real tool runs.

```bash
npm install toolgovern-integration-langgraph @langchain/core @langchain/langgraph toolgovern
```

## Why this package exists

LangGraph.js's `ToolNode` constructor only accepts `{name, tags, handleToolErrors}` -- there is no
`wrap_tool_call` hook. That hook exists only in the separately maintained Python `langgraph`
package (`langchain-ai/langgraph`), confirmed by reading
`libs/langgraph-core/src/prebuilt/tool_node.ts` in the real `langchain-ai/langgraphjs` source.
There is no way to intercept a call from inside `ToolNode` itself in the JS/TS package.

The working integration point is one level up, at tool-definition time: wrap each tool with
`governTool()`, then re-wrap the governed callable with LangChain's own `tool()` factory (from
`@langchain/core/tools`, a fully public API) so the result is still a real
`StructuredToolInterface`. No monkey-patching of `ToolNode` or LangChain internals -- the governed
tool is a drop-in replacement anywhere a LangChain tool is expected.

## Quick example

```ts
import { z } from 'zod';
import { tool } from '@langchain/core/tools';
import { ToolNode } from '@langchain/langgraph/prebuilt';
import { governedLangGraphTools } from 'toolgovern-integration-langgraph';
import { loadPolicy } from 'toolgovern';

const getWeather = tool((input: { location: string }) => `It's sunny in ${input.location}.`, {
  name: 'get_weather',
  description: 'Call to get the current weather.',
  schema: z.object({ location: z.string() }),
});

const policy = loadPolicy('./toolgovern.policy.yml');

const governedTools = governedLangGraphTools([getWeather], {
  ...policy,
  agentId: 'research-sub',
  sessionId: 'demo-session',
});

const toolNode = new ToolNode(governedTools);
// wire toolNode into your StateGraph exactly as you would with the raw tools array --
// every call now flows through toolgovern's classifier first.
```

A denied call throws `ToolGovernDenialError` from inside the wrapped tool's `func`. With
`ToolNode`'s default `handleToolErrors: true`, that surfaces as a `ToolMessage` with
`status: 'error'` on the returned message, not a silent pass-through.

## API

### `governedLangGraphTool(tool, options)`

Wraps a single `StructuredToolInterface` (anything built with LangChain's `tool()` factory, or any
`DynamicTool`/`DynamicStructuredTool`). Returns a new `StructuredToolInterface` with the same
`name`, `description`, and `schema` -- only the execution path is gated. `options` is a
`GovernToolOptions` from `toolgovern` (the same shape `governTool()` and `loadPolicy()` use).

### `governedLangGraphTools(tools, options)`

Wraps a whole array of tools in one call -- the common case, since both `ToolNode` and
`bindTools()` take a tools array. Every tool shares the same `options` (same agent identity,
scope, and trace); call `governedLangGraphTool` directly per tool if different tools need
different scopes.

## What this does not claim

This package adds new LangGraph.js capability -- it does not retroactively fix any previously
reported issue. Every LangGraph issue this project has validated against a real repository was
filed against the Python `langchain-ai/langgraph` package, not `langgraphjs`; this package targets
a different runtime and a different (currently unreported-against) codebase.

See the [full toolgovern documentation](https://github.com/RudrenduPaul/toolgovern) on GitHub for
the middleware itself, the rule pack, and the trace format spec.

## License

Apache 2.0. See [LICENSE](https://github.com/RudrenduPaul/toolgovern/blob/main/LICENSE).
