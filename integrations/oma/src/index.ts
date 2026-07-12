/**
 * integrations/oma -- documented adapter shapes for wiring `toolgovern` into an open
 * multi-agent framework's tool-executor call site.
 *
 * IMPORTANT: this is a generic reference adapter, not a submitted or merged integration against
 * any specific upstream project. It has not been contributed upstream to any framework.
 *
 * Two shapes are provided, matching the two real integration patterns multi-agent frameworks
 * actually use:
 *
 * 1. `governedTool()` -- per-tool, registration-time wrapping. This is the pattern OMA's own
 *    reference implementation (`node_runner`'s `wrapToolWithEvents()`) actually uses: wrap one
 *    `{name, execute}` tool at the point it's registered, before it's added to a tool registry.
 *    Start here unless the framework you're integrating genuinely has a single dispatcher.
 *
 *    Usage:
 *
 *      import { governedTool } from 'toolgovern-integration-oma'
 *      import { loadPolicy } from 'toolgovern'
 *
 *      const policy = loadPolicy('./toolgovern.policy.yml')
 *      registry.register(governedTool(myTool, policy))
 *
 * 2. `governedExecutor()` -- wraps a whole `ToolExecutorLike.runTool(name, args)` dispatcher
 *    object, for frameworks whose tool-executor layer is a single dispatch point rather than
 *    per-tool registration. Method and field names on `ToolExecutorLike` are illustrative, not a
 *    claim about any specific framework's actual API -- adjust it to match the real interface
 *    you are integrating against.
 *
 *    Usage:
 *
 *      import { governedExecutor } from 'toolgovern-integration-oma'
 *      import { loadPolicy } from 'toolgovern'
 *
 *      const policy = loadPolicy('./toolgovern.policy.yml')
 *      const executor = governedExecutor(baseExecutor, policy)
 *
 *      // wherever the framework currently calls baseExecutor.runTool(name, args) directly,
 *      // call executor.runTool(name, args) instead -- every call now flows through the
 *      // classifier first.
 */

import { governTool, type GovernToolOptions, type ToolDefinition } from 'toolgovern';

/**
 * Wraps a single tool for per-tool, registration-time wrapping -- the pattern OMA's own
 * reference implementation (node_runner's `wrapToolWithEvents()`) actually uses. This is a thin,
 * OMA-documented alias for toolgovern's own `governTool()` -- the shapes are already identical
 * (`ToolDefinition = {name, execute}`), so there is no OMA-specific adaptation logic needed here,
 * only OMA-specific usage documentation pointing integrators at the right pattern.
 */
export function governedTool<Args extends Record<string, unknown>, Result>(
  tool: ToolDefinition<Args, Result>,
  options: GovernToolOptions,
): ToolDefinition<Args, Result> {
  return governTool(tool, options);
}

/**
 * The minimal shape a framework's tool-executor needs to expose for `governedExecutor` to wrap
 * it. An alternate shape for frameworks whose tool-executor is a single `runTool(name, args)`
 * dispatcher rather than per-tool registration -- OMA's own real implementation uses the
 * per-tool `governedTool()` pattern above; this one is kept for frameworks that genuinely have a
 * dispatcher-style executor.
 */
export interface ToolExecutorLike {
  runTool(toolName: string, args: Record<string, unknown>): Promise<unknown> | unknown;
}

/**
 * Wraps `baseExecutor` so every `runTool()` call is evaluated by toolgovern's classifier before
 * it reaches the framework's real tool implementation. One `governedExecutor` instance
 * corresponds to one agent identity (root or sub-agent) -- `options` carries that identity via
 * `agentId` / `sessionId` / `coordinatorId`, the same as a direct `governTool()` call.
 */
export function governedExecutor(
  baseExecutor: ToolExecutorLike,
  options: GovernToolOptions,
): ToolExecutorLike {
  const governedByToolName = new Map<string, ToolDefinition>();

  function getGoverned(toolName: string): ToolDefinition {
    const existing = governedByToolName.get(toolName);
    if (existing) return existing;

    const rawTool: ToolDefinition = {
      name: toolName,
      execute: (args: Record<string, unknown>) => baseExecutor.runTool(toolName, args),
    };
    const wrapped = governTool(rawTool, options);
    governedByToolName.set(toolName, wrapped);
    return wrapped;
  }

  return {
    async runTool(toolName: string, args: Record<string, unknown>): Promise<unknown> {
      return getGoverned(toolName).execute(args);
    },
  };
}
