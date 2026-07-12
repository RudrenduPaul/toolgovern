/**
 * integrations/oma -- a generic, documented adapter shape for wiring `toolgovern` into an open
 * multi-agent framework's tool-executor call site.
 *
 * IMPORTANT: this is a generic reference adapter, not a submitted or merged integration against
 * any specific upstream project. It has not been contributed upstream to any framework. The
 * shape below (`ToolExecutorLike.runTool(toolName, args)`) models a common pattern multi-agent
 * frameworks use for their tool-executor layer -- close to what a framework's own
 * `ToolExecutor.runTool()` call site typically looks like -- so that whoever wires `toolgovern`
 * into a real framework has a concrete, working starting point to adapt rather than starting
 * from zero. Method and field names here are illustrative, not a claim about any specific
 * framework's actual API. Adjust `ToolExecutorLike` to match the real interface you are
 * integrating against.
 *
 * Usage:
 *
 *   import { governedExecutor } from 'toolgovern-integration-oma'
 *   import { loadPolicy } from 'toolgovern'
 *
 *   const policy = loadPolicy('./toolgovern.policy.yml')
 *   const executor = governedExecutor(baseExecutor, policy)
 *
 *   // wherever the framework currently calls baseExecutor.runTool(name, args) directly,
 *   // call executor.runTool(name, args) instead -- every call now flows through the classifier
 *   // first.
 */

import { governTool, type GovernToolOptions, type ToolDefinition } from 'toolgovern';

/**
 * The minimal shape a framework's tool-executor needs to expose for this adapter to wrap it.
 * Most multi-agent frameworks have something structurally equivalent, even if the real method
 * name differs (e.g. `execute`, `invoke`, `call`).
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
