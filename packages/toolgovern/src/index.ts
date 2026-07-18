/**
 * toolgovern -- runtime governance middleware for AI agent tool calls.
 *
 * A gated call never reaches the wrapped tool's real implementation until the classifier
 * returns `allow`. Every decision is traceable to a specific rule ID; there is no unexplained
 * black-box denial. `governTool()` evaluating a call as `allow` means the call was checked
 * against the current rule set -- it is not a guarantee the call is safe.
 */

export * from './types.js';
export * from './middleware/index.js';
export * from './classifier/index.js';
export * from './scoping/index.js';
export * from './trace/index.js';
export * from './policy/index.js';
export * from './approval/pending-registry.js';
export * from './mcp-trust/index.js';
