/**
 * integrations/langgraph -- routes LangGraph.js tool calls through toolgovern's governTool()
 * gate before they ever reach a LangChain tool() call site, so a governed tool slots into
 * `new ToolNode([...tools])` unchanged.
 *
 * IMPORTANT: LangGraph.js's `ToolNode` constructor (confirmed by reading
 * `libs/langgraph-core/src/prebuilt/tool_node.ts` in `langchain-ai/langgraphjs`) only accepts
 * `{name, tags, handleToolErrors}` -- there is no `wrap_tool_call` hook. That hook exists only
 * in the separately maintained Python `langchain-ai/langgraph` package. The Node-native
 * integration point is therefore one level up, at tool-definition time: wrap the underlying tool
 * with `governTool()`, then re-wrap the governed callable with LangChain's own `tool()` factory
 * (`@langchain/core/tools`, a fully public API) so the result is still a real
 * `StructuredToolInterface` -- no monkey-patching of `ToolNode` or LangChain internals.
 *
 * Usage:
 *
 *   import { governedLangGraphTools } from 'toolgovern-integration-langgraph';
 *   import { ToolNode } from '@langchain/langgraph/prebuilt';
 *   import { loadPolicy } from 'toolgovern';
 *
 *   const policy = loadPolicy('./toolgovern.policy.yml');
 *   const toolNode = new ToolNode(governedLangGraphTools(myLangChainTools, policy));
 */

import { tool } from '@langchain/core/tools';
import type { StructuredToolInterface } from '@langchain/core/tools';
import { governTool, type GovernToolOptions, type ToolDefinition } from 'toolgovern';

/**
 * Wraps one LangChain/LangGraph.js tool so every invocation is evaluated by toolgovern's
 * classifier before the tool's real `.invoke()` runs. The returned tool keeps the original
 * name, description, and schema -- it is a drop-in replacement in a `new ToolNode([...])` tools
 * array, a `bindTools()` call, or anywhere else a `StructuredToolInterface` is expected.
 *
 * A `deny` decision throws `ToolGovernDenialError` from inside the wrapped tool's func, the same
 * as a plain `governTool()`-wrapped tool -- `ToolNode` surfaces that as a rejected call, it is
 * never silently swallowed.
 */
export function governedLangGraphTool(
  langchainTool: StructuredToolInterface,
  options: GovernToolOptions,
): StructuredToolInterface {
  const rawTool: ToolDefinition<Record<string, unknown>, unknown> = {
    name: langchainTool.name,
    execute: (args) => langchainTool.invoke(args),
  };

  const governed = governTool(rawTool, options);

  return tool(async (input) => governed.execute(input as Record<string, unknown>), {
    name: langchainTool.name,
    description: langchainTool.description || `${langchainTool.name} tool`,
    schema: langchainTool.schema,
  }) as unknown as StructuredToolInterface;
}

/**
 * Wraps a whole array of LangChain/LangGraph.js tools in one call -- the common case, since
 * `ToolNode` and `bindTools()` both take a tools array. Every tool shares the same
 * `GovernToolOptions` (same agent identity, scope, and trace); call `governedLangGraphTool`
 * directly per tool if different tools need different scopes.
 */
export function governedLangGraphTools(
  langchainTools: readonly StructuredToolInterface[],
  options: GovernToolOptions,
): StructuredToolInterface[] {
  return langchainTools.map((t) => governedLangGraphTool(t, options));
}

export type { GovernToolOptions, ToolDefinition } from 'toolgovern';
export type { StructuredToolInterface } from '@langchain/core/tools';
