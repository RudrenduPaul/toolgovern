/**
 * `governTool()` -- the core hook. Wraps any tool definition a framework already has and
 * returns a version that evaluates every invocation through the classifier before the
 * underlying tool executes. No framework fork required: this is designed to slot into a single
 * call site (e.g. a `ToolExecutor.runTool()` wrapper) with one wrapping call.
 *
 * A gated call never reaches the real tool implementation until the classifier's decision
 * resolves to `allow`. `deny` throws `ToolGovernDenialError` without executing the tool at all.
 * `require-approval` calls `onApprovalRequired` if one was provided; with no handler, or if the
 * handler times out, the call fails closed (denied) -- an unanswered approval request is never
 * treated as a yes.
 */

import type {
  AgentIdSource,
  Decision,
  Policy,
  RuleContext,
  RuleMatch,
  ScopeDeclaration,
} from '../types.js';
import { classify } from '../classifier/index.js';
import type { ScopeRegistry } from '../scoping/inheritance-enforcer.js';
import { isValidAgentId } from '../scoping/scope-declaration.js';
import type { TraceWriter } from '../trace/trace-writer.js';

export interface ToolDefinition<
  Args extends Record<string, unknown> = Record<string, unknown>,
  Result = unknown,
> {
  readonly name: string;
  execute(args: Args): Promise<Result> | Result;
}

/** Everything surfaced to `onApprovalRequired` and `onDecision` about one gate decision. */
export interface GateDecisionInfo {
  readonly agentId: string;
  readonly sessionId: string;
  readonly coordinatorId?: string;
  readonly tool: string;
  readonly args: Readonly<Record<string, unknown>>;
  readonly decision: Decision;
  readonly firedRules: readonly RuleMatch[];
  readonly scope: ScopeDeclaration;
}

export type ApprovalHandler = (info: GateDecisionInfo) => Promise<boolean> | boolean;

export interface GovernToolOptions extends Policy {
  readonly scopeRegistry?: ScopeRegistry;
  readonly trace?: TraceWriter;
  /** Called only for `require-approval` decisions. Return/resolve `true` to allow the call
   *  through, `false` to deny it. Omitted entirely means every `require-approval` decision is
   *  denied (fail-closed) -- there is no such thing as an implicit approval. */
  readonly onApprovalRequired?: ApprovalHandler;
  /** How long to wait for `onApprovalRequired` before treating it as a denial. Defaults to 30s,
   *  matching the human-in-the-loop timeout shown in the product spec's sample gate output. */
  readonly approvalTimeoutMs?: number;
  /** Fires after every gate decision, allow/deny/require-approval alike, after the trace entry
   *  (if any) has been written. Useful for a live console/log, not part of the gate itself. */
  readonly onDecision?: (info: GateDecisionInfo) => void;
}

const DEFAULT_APPROVAL_TIMEOUT_MS = 30_000;

export class ToolGovernDenialError extends Error {
  constructor(public readonly decisionInfo: GateDecisionInfo) {
    const ruleIds = decisionInfo.firedRules.map((r) => r.ruleId).join(', ') || 'policy default';
    super(
      `toolgovern denied tool call "${decisionInfo.tool}" (agent "${decisionInfo.agentId}"): ${ruleIds}`,
    );
    this.name = 'ToolGovernDenialError';
  }
}

/**
 * Thrown by `governTool()` when an explicitly-supplied `options.agentId` fails the format check
 * in `isValidAgentId()` (empty, excessively long, or containing control/injection-style
 * characters). This is a format rejection, not an identity-verification failure -- toolgovern
 * cannot tell a malformed `agentId` apart from a well-formed one that is still a lie; it can only
 * refuse to treat obviously-malformed input as an identity at all. See
 * `docs/security-model.md`, "Agent identity is caller-asserted, not cryptographically verified."
 */
export class InvalidAgentIdError extends Error {
  constructor(public readonly rawAgentId: string) {
    super(
      `toolgovern rejected a malformed agentId: ${JSON.stringify(rawAgentId)}. It must be a ` +
        'non-empty string, no longer than 256 characters, with no control characters. This is a ' +
        'format check only -- it does not verify the caller actually is the agent it claims to be.',
    );
    this.name = 'InvalidAgentIdError';
  }
}

function resolveEffectiveScope(
  options: GovernToolOptions,
  agentId: string,
  sessionId: string,
): ScopeDeclaration {
  const { scopeRegistry, coordinatorId, scope } = options;
  if (!scopeRegistry) return scope;

  const existing = scopeRegistry.getRecord(agentId);
  if (existing) return existing.grantedScope;

  if (coordinatorId) {
    return scopeRegistry.spawnSubAgent({
      coordinatorId,
      subAgentId: agentId,
      sessionId,
      requestedScope: scope,
    }).grantedScope;
  }
  return scopeRegistry.registerRootAgent(agentId, sessionId, scope).grantedScope;
}

async function resolveApproval(
  handler: ApprovalHandler | undefined,
  info: GateDecisionInfo,
  timeoutMs: number,
): Promise<boolean> {
  if (!handler) return false;
  // A handler that throws (sync or async) must fail closed exactly like "no handler" or "timed
  // out" -- it must NOT propagate out of governTool(), because that would skip the trace-append
  // call below and surface a raw, unrelated error instead of ToolGovernDenialError. An
  // unanswerable approval request is a denial, not an application crash.
  const handlerResult = Promise.resolve()
    .then(() => handler(info))
    .catch(() => false);
  const timeout = new Promise<boolean>((resolve) => {
    setTimeout(() => resolve(false), timeoutMs);
  });
  return Promise.race([handlerResult, timeout]);
}

/**
 * Wraps `tool` so every call is evaluated by the classifier before it executes. `options` is a
 * `Policy` (whether hand-written inline or returned by `loadPolicy()`) plus optional runtime
 * wiring (`scopeRegistry`, `trace`, approval handling).
 */
export function governTool<Args extends Record<string, unknown>, Result>(
  tool: ToolDefinition<Args, Result>,
  options: GovernToolOptions,
): ToolDefinition<Args, Result> {
  // `agentId` is a caller-asserted string, never cryptographically verified (see
  // `docs/security-model.md`). What we CAN do here is reject a malformed one outright -- a claim
  // that isn't even well-formed shouldn't be treated as an identity at all -- and record whether
  // this call's `agentId` was explicitly supplied or fell back to the default, so an auditor
  // reading the trace later can see which kind of (still-unverified) claim backed the decision.
  if (options.agentId !== undefined && !isValidAgentId(options.agentId)) {
    throw new InvalidAgentIdError(options.agentId);
  }
  const agentIdSource: AgentIdSource = options.agentId !== undefined ? 'explicit' : 'fallback';
  const agentId = options.agentId ?? 'default-agent';
  const sessionId = options.sessionId ?? 'default-session';
  const coordinatorId = options.coordinatorId;
  const disabledRules = options.rules?.disable ?? [];
  const downgradeToApproval = options.rules?.requireApproval ?? [];
  const defaultDecision = options.defaultDecision ?? 'allow';
  const approvalTimeoutMs = options.approvalTimeoutMs ?? DEFAULT_APPROVAL_TIMEOUT_MS;

  return {
    name: tool.name,
    async execute(args: Args): Promise<Result> {
      const effectiveScope = resolveEffectiveScope(options, agentId, sessionId);

      const ruleContext: RuleContext = {
        agentId,
        sessionId,
        coordinatorId,
        tool: tool.name,
        args,
        scope: effectiveScope,
        scopeRegistry: options.scopeRegistry,
      };

      const classifierResult = classify(ruleContext, { disabledRules, downgradeToApproval });
      let decision: Decision = classifierResult.decision;
      const firedRules = classifierResult.firedRules;

      // A `defaultDecision` other than `allow` only applies when the classifier found nothing to
      // flag -- it never overrides an explicit rule verdict.
      if (firedRules.length === 0 && defaultDecision !== 'allow') {
        decision = defaultDecision;
      }

      const info: GateDecisionInfo = {
        agentId,
        sessionId,
        coordinatorId,
        tool: tool.name,
        args,
        decision,
        firedRules,
        scope: effectiveScope,
      };

      let finalDecision: Decision = decision;
      if (decision === 'require-approval') {
        const approved = await resolveApproval(options.onApprovalRequired, info, approvalTimeoutMs);
        finalDecision = approved ? 'allow' : 'deny';
      }

      if (options.trace) {
        const ruleFiredIds =
          firedRules.length > 0
            ? firedRules.map((r) => r.ruleId)
            : decision !== 'allow'
              ? ['policy-default-decision']
              : [];
        await options.trace.append({
          sessionId,
          agentId,
          tool: tool.name,
          args,
          decision,
          ruleFired: ruleFiredIds,
          declaredScope: effectiveScope,
          agentIdSource,
        });
      }

      options.onDecision?.(info);

      if (finalDecision === 'deny') {
        throw new ToolGovernDenialError(info);
      }
      return tool.execute(args);
    },
  };
}
