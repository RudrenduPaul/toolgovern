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

import type { Decision, Policy, RuleContext, RuleMatch, ScopeDeclaration } from '../types.js';
import { classify } from '../classifier/index.js';
import type { ScopeRegistry } from '../scoping/inheritance-enforcer.js';
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

/** What an `ApprovalHandler` resolves to when it wants to record who made the call, not just
 *  whether it was approved. A handler may still return a plain `boolean` -- `approvedBy` is
 *  optional identity metadata, never required to resolve an approval. */
export interface ApprovalOutcome {
  readonly approved: boolean;
  /** Identity of the human who approved or denied the call (e.g. an email, username, or ticket
   *  ID). Recorded on the trace entry as `approved_by` when present. */
  readonly approvedBy?: string;
}

export type ApprovalHandler = (
  info: GateDecisionInfo,
) => Promise<boolean | ApprovalOutcome> | boolean | ApprovalOutcome;

export interface GovernToolOptions extends Policy {
  readonly scopeRegistry?: ScopeRegistry;
  readonly trace?: TraceWriter;
  /** Called only for `require-approval` decisions. Return/resolve `true` to allow the call
   *  through, `false` to deny it -- or an `ApprovalOutcome` to also record who decided. Omitted
   *  entirely means every `require-approval` decision is denied (fail-closed) -- there is no
   *  such thing as an implicit approval. */
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

function normalizeApprovalResult(result: boolean | ApprovalOutcome): ApprovalOutcome {
  return typeof result === 'boolean' ? { approved: result } : result;
}

async function resolveApproval(
  handler: ApprovalHandler | undefined,
  info: GateDecisionInfo,
  timeoutMs: number,
): Promise<ApprovalOutcome> {
  if (!handler) return { approved: false };
  // A handler that throws (sync or async) must fail closed exactly like "no handler" or "timed
  // out" -- it must NOT propagate out of governTool(), because that would skip the trace-append
  // call below and surface a raw, unrelated error instead of ToolGovernDenialError. An
  // unanswerable approval request is a denial, not an application crash.
  const handlerResult = Promise.resolve()
    .then(() => handler(info))
    .then(normalizeApprovalResult)
    .catch((): ApprovalOutcome => ({ approved: false }));
  const timeout = new Promise<ApprovalOutcome>((resolve) => {
    setTimeout(() => resolve({ approved: false }), timeoutMs);
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
      let approvedBy: string | undefined;
      if (decision === 'require-approval') {
        const outcome = await resolveApproval(options.onApprovalRequired, info, approvalTimeoutMs);
        finalDecision = outcome.approved ? 'allow' : 'deny';
        approvedBy = outcome.approvedBy;
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
          decision: finalDecision,
          ruleFired: ruleFiredIds,
          declaredScope: effectiveScope,
          approvedBy,
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
