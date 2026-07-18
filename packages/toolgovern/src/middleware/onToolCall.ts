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
import { classifyAsync } from '../classifier/index.js';
import type { ScopeRegistry } from '../scoping/inheritance-enforcer.js';
import { isValidAgentId } from '../scoping/scope-declaration.js';
import type { TraceWriter } from '../trace/trace-writer.js';
import { IdempotencyCache, type IdempotencyOptions } from './idempotency-cache.js';
import type { PendingApprovalRegistry, ResolvePendingInput } from '../approval/pending-registry.js';

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
  /** The durable `PendingApprovalRegistry` id for this decision, when `options.pendingApprovals`
   *  was supplied and this decision was `require-approval`. Lets an `onDecision` listener
   *  correlate the in-process (synchronous) outcome with the durable record a webhook/CLI/review
   *  queue can later resolve via `resolvePending()`. Absent for every other decision, and absent
   *  entirely when no `pendingApprovals` registry was configured. */
  readonly pendingId?: string;
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
  /**
   * Optional durable registry for `require-approval` decisions. When supplied, every
   * `require-approval` decision is persisted here (via `registerPending()`) BEFORE
   * `onApprovalRequired` (if any) is invoked -- so a caller who is not the in-process handler (a
   * webhook, a CLI command, a human review queue) can resolve the same decision later via
   * `resolvePending()`, independent of this call's own 30-second synchronous window. Once the
   * synchronous path resolves (approved, denied, timed out, or handler-threw), that outcome is
   * reflected back into the registry so the entry reads `'resolved'` and a later out-of-band
   * `resolvePending()` call correctly gets `'already-resolved'` rather than re-deciding (or, for
   * a side-effecting tool, re-executing) the same call twice. Omitted entirely -- the default --
   * leaves `governTool()`'s behavior completely unchanged: the synchronous `onApprovalRequired`
   * path is the only path, exactly as before this option existed. See
   * `approval/pending-registry.ts` and `resumePendingApproval()` below.
   */
  readonly pendingApprovals?: PendingApprovalRegistry;
  /** Fires after every gate decision, allow/deny/require-approval alike, after the trace entry
   *  (if any) has been written. Useful for a live console/log, not part of the gate itself. */
  readonly onDecision?: (info: GateDecisionInfo) => void;
  /**
   * Optional post-execution hook. Once a call is allowed and `tool.execute()` has run (or
   * thrown), the raw result -- or the thrown error, if `execute()` rejected/threw -- is passed
   * through this function before anything is returned to the caller. Whatever `onToolResult`
   * returns is what the gated tool actually returns, which is the only supported way to
   * redact, sanitize, or otherwise gate a tool's *output* (v0.1's classifier only evaluates
   * pre-execution arguments). This is intentionally scoped: there is no signal distinguishing a
   * success value from a caught error other than `instanceof Error` (or similar) on the first
   * argument -- callers that need to keep treating tool errors as errors should re-throw from
   * inside this hook. Omitted entirely means the raw result/error passes straight through
   * unchanged, so this is fully backward-compatible.
   */
  readonly onToolResult?: (result: unknown, ctx: RuleContext) => unknown;
  /** Optional in-memory retry dedup for tools with real-world side effects (payments, emails,
   *  trades) where a caller retrying after a timeout or transient failure must not cause the
   *  effect to fire twice. Omitted entirely -- the default -- leaves this middleware's behavior
   *  completely unchanged: every call still executes independently. When enabled, an identical
   *  retry (same tool name + same arguments) within `ttlMs` of a completed call returns the
   *  cached result instead of calling `tool.execute()` again. This only affects the final
   *  `tool.execute()` call, not classification: the classifier still evaluates every call and
   *  `trace`/`onDecision` still fire every time, so the gate/audit trail is unaffected.
   *
   *  This is an in-memory-only first pass, not a distributed/persistent cache: it does not
   *  survive a process restart and is not shared across multiple processes or replicas. See
   *  `idempotency-cache.ts` for the full scope and limitations. */
  readonly idempotency?: IdempotencyOptions;
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

function normalizeApprovalResult(result: boolean | ApprovalOutcome): ApprovalOutcome {
  return typeof result === 'boolean' ? { approved: result } : result;
}

/** What actually happened when `governTool()` tried to resolve a `require-approval` decision
 *  through the synchronous in-process path. `answered: true` means `handler` itself genuinely
 *  produced a result before the timeout -- a real decision, whether allow or deny. `answered:
 *  false` covers every case where nothing genuine came back: no handler was provided, the
 *  handler threw, or it simply didn't resolve before `timeoutMs`. This distinction is what lets
 *  `execute()` decide whether a `pendingApprovals` registry entry should be closed out as
 *  terminally resolved (a real decision was made) or left `'pending'` for a later out-of-band
 *  `resolvePending()`/`resumePendingApproval()` call to actually resolve (nothing was ever
 *  decided synchronously -- this call merely gave up waiting within its own window). Either way,
 *  THIS `execute()` invocation still fails closed (denies) when `answered` is `false`, exactly as
 *  before this distinction existed -- only the registry's own bookkeeping changes. */
interface ApprovalResolution {
  readonly outcome: ApprovalOutcome;
  readonly answered: boolean;
}

async function resolveApproval(
  handler: ApprovalHandler | undefined,
  info: GateDecisionInfo,
  timeoutMs: number,
): Promise<ApprovalResolution> {
  if (!handler) return { outcome: { approved: false }, answered: false };
  // A handler that throws (sync or async) must fail closed exactly like "no handler" or "timed
  // out" -- it must NOT propagate out of governTool(), because that would skip the trace-append
  // call below and surface a raw, unrelated error instead of ToolGovernDenialError. An
  // unanswerable approval request is a denial, not an application crash.
  const handlerResult: Promise<ApprovalResolution> = Promise.resolve()
    .then(() => handler(info))
    .then((result): ApprovalResolution => ({
      outcome: normalizeApprovalResult(result),
      answered: true,
    }))
    .catch((): ApprovalResolution => ({ outcome: { approved: false }, answered: false }));
  let timeoutHandle: ReturnType<typeof setTimeout>;
  const timeout = new Promise<ApprovalResolution>((resolve) => {
    timeoutHandle = setTimeout(
      () => resolve({ outcome: { approved: false }, answered: false }),
      timeoutMs,
    );
  });
  try {
    return await Promise.race([handlerResult, timeout]);
  } finally {
    clearTimeout(timeoutHandle!);
  }
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
  // Scoped to this one gated tool instance -- never shared globally across every gate in a
  // process. See idempotency-cache.ts for why this is in-memory-only, not a full solution.
  const idempotencyCache = options.idempotency?.enabled
    ? new IdempotencyCache<Result>(options.idempotency.ttlMs)
    : undefined;

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

      // classifyAsync (not the synchronous classify()) so TG03's DNS-resolution check
      // (TG03-dns-resolves-private) actually runs -- execute() is already async end-to-end, so
      // there is no reason for this call path to silently skip an async-only rule.
      const classifierResult = await classifyAsync(ruleContext, {
        disabledRules,
        downgradeToApproval,
      });
      let decision: Decision = classifierResult.decision;
      const firedRules = classifierResult.firedRules;

      // A `defaultDecision` other than `allow` only applies when the classifier found nothing to
      // flag -- it never overrides an explicit rule verdict.
      if (firedRules.length === 0 && defaultDecision !== 'allow') {
        decision = defaultDecision;
      }

      // Registered BEFORE `onApprovalRequired` is invoked (or even looked at), so a durable
      // record of this decision exists regardless of whether the synchronous handler answers,
      // times out, throws, or was never provided at all -- see `pendingApprovals` above.
      let pendingId: string | undefined;
      if (decision === 'require-approval' && options.pendingApprovals) {
        pendingId = options.pendingApprovals.registerPending({
          agentId,
          sessionId,
          coordinatorId,
          tool: tool.name,
          args,
          scope: effectiveScope,
          firedRules,
          agentIdSource,
          disabledRules,
          downgradeToApproval,
        });
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
        pendingId,
      };

      let finalDecision: Decision = decision;
      let approvedBy: string | undefined;
      if (decision === 'require-approval') {
        const { outcome, answered } = await resolveApproval(
          options.onApprovalRequired,
          info,
          approvalTimeoutMs,
        );
        finalDecision = outcome.approved ? 'allow' : 'deny';
        approvedBy = outcome.approvedBy;

        // Only reflect this outcome back into the durable registry when the synchronous handler
        // actually, genuinely answered (`answered === true`) -- a real human (or automation)
        // decision, allow or deny, is terminal: a later resolvePending()/resumePendingApproval()
        // call must get 'already-resolved', never a chance to re-decide or (for a side-effecting
        // tool) re-execute a call this process already finished with.
        //
        // When NOTHING genuinely answered (no handler was configured, the handler threw, or it
        // simply didn't resolve within `approvalTimeoutMs`), this specific `execute()` call still
        // fails closed exactly as before -- but the registry entry is deliberately left
        // `'pending'`. That is the entire point of `pendingApprovals`: a caller running with a
        // short/no synchronous window relies on this call denying quickly while the REAL approval
        // is expected to arrive later and out of band (a webhook, a CLI command, a human review
        // queue) via `resolvePending()`/`resumePendingApproval()` -- reflecting a fail-closed
        // default back as if it were a real decision would make that async path permanently
        // unreachable.
        if (pendingId && options.pendingApprovals && answered) {
          await options.pendingApprovals.resolvePending(pendingId, {
            decision: finalDecision,
            approvedBy,
          });
        }
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
          agentIdSource,
        });
      }

      options.onDecision?.(info);

      if (finalDecision === 'deny') {
        throw new ToolGovernDenialError(info);
      }

      // A thrown/rejected `execute()` (whether run directly or via the idempotency cache below)
      // is caught here rather than left to propagate directly, so `onToolResult` (when provided)
      // gets a chance to see it -- e.g. to redact a leaked file path in an error message --
      // before anything reaches the caller. With no `onToolResult`, behavior is unchanged: a
      // caught error is simply rethrown.
      try {
        const result = idempotencyCache
          ? await idempotencyCache.claimIfAbsent(IdempotencyCache.keyFor(tool.name, args), () =>
              Promise.resolve(tool.execute(args)),
            )
          : await tool.execute(args);
        return options.onToolResult
          ? (options.onToolResult(result, ruleContext) as Result)
          : result;
      } catch (error) {
        if (options.onToolResult) {
          return options.onToolResult(error, ruleContext) as Result;
        }
        throw error;
      }
    },
  };
}

/** Raised by `resumePendingApproval()` when the `pendingId` it was given cannot be resolved to a
 *  fresh, actionable decision -- either because it (or its alias) is unrecognized, because it was
 *  already resolved by an earlier call (the synchronous path timing out, or a previous resume),
 *  or because it expired. This is deliberately a different error from `ToolGovernDenialError`:
 *  a denial is a real classifier/human verdict on the call; this is "there was nothing here left
 *  to resolve," which callers (a webhook handler, say) generally need to handle differently (e.g.
 *  respond 409/404 rather than "your request was denied"). */
export class PendingApprovalNotResolvableError extends Error {
  constructor(
    public readonly pendingId: string,
    public readonly status: 'not-found' | 'already-resolved' | 'expired',
  ) {
    super(
      `toolgovern: pending approval ${JSON.stringify(pendingId)} could not be resolved (${status}).`,
    );
    this.name = 'PendingApprovalNotResolvableError';
  }
}

/** Optional wiring `resumePendingApproval()` accepts -- deliberately the same shape of
 *  `trace`/`onDecision`/`onToolResult` options `governTool()` itself accepts, so a caller resuming
 *  a pending approval gets the same trace/observability behavior as the original synchronous
 *  call would have. */
export interface ResumePendingApprovalOptions {
  readonly trace?: TraceWriter;
  readonly onDecision?: (info: GateDecisionInfo) => void;
  readonly onToolResult?: (result: unknown, ctx: RuleContext) => unknown;
}

/**
 * Closes the loop `pendingApprovals` opens: given the SAME `tool` definition `governTool()` was
 * originally wrapping, a `PendingApprovalRegistry` that call registered its `require-approval`
 * decision in, the `pendingId` it was given back, and a resolution (allow/deny, optionally with
 * `editedArgs`), this resolves the pending approval and -- if and only if the resolution (after
 * any edited-args re-classification) comes back `allow` -- actually invokes `tool.execute()` with
 * the effective arguments, appends one trace entry with `approvedBy` populated exactly as the
 * synchronous path does, and returns the tool's result.
 *
 * This is the piece of the "durable, resumable approval" story that runs OUTSIDE the original
 * `governTool(...).execute()` call -- from a webhook handler, a CLI command, or a long-running
 * human review queue's worker loop, any time after that original call already returned (denied,
 * most likely, if nothing answered its 30-second synchronous window). It does not, and cannot,
 * resume that ORIGINAL `execute()` call's own promise -- that promise already settled. What it
 * does is perform the actual, real, gated execution the human's later decision authorizes,
 * through the identical classify -> gate -> execute -> trace pipeline, so an edited/approved call
 * still cannot skip re-classification (see `PendingApprovalRegistry#resolvePending`) and still
 * produces a real audit trail.
 *
 * Throws `PendingApprovalNotResolvableError` if the pending approval is unrecognized, already
 * resolved, or expired -- never silently does nothing. Throws `ToolGovernDenialError` if the
 * resolution (or its edited-args re-classification) is a `deny` -- `tool.execute()` is never
 * called in that case, exactly like a live `governTool()` denial.
 */
export async function resumePendingApproval<Args extends Record<string, unknown>, Result>(
  tool: ToolDefinition<Args, Result>,
  registry: PendingApprovalRegistry,
  pendingId: string,
  resolution: ResolvePendingInput,
  options: ResumePendingApprovalOptions = {},
): Promise<Result> {
  const pending = registry.get(pendingId);
  const outcome = await registry.resolvePending(pendingId, resolution);

  if (outcome.status !== 'resolved') {
    throw new PendingApprovalNotResolvableError(pendingId, outcome.status);
  }

  const effectiveArgs = (outcome.args ?? pending?.args ?? {}) as Args;
  const firedRules = outcome.firedRules ?? pending?.firedRules ?? [];
  const scope = pending?.scope ?? { network: false, filesystem: [], credentials: [] };
  const finalDecision: Decision = outcome.finalDecision === 'allow' ? 'allow' : 'deny';

  const info: GateDecisionInfo = {
    agentId: pending?.agentId ?? 'default-agent',
    sessionId: pending?.sessionId ?? 'default-session',
    coordinatorId: pending?.coordinatorId,
    tool: pending?.tool ?? tool.name,
    args: effectiveArgs,
    decision: finalDecision,
    firedRules,
    scope,
    pendingId,
  };

  if (options.trace) {
    const ruleFiredIds =
      firedRules.length > 0
        ? firedRules.map((r) => r.ruleId)
        : finalDecision !== 'allow'
          ? ['policy-default-decision']
          : [];
    await options.trace.append({
      sessionId: info.sessionId,
      agentId: info.agentId,
      tool: info.tool,
      args: effectiveArgs,
      decision: finalDecision,
      ruleFired: ruleFiredIds,
      declaredScope: scope,
      approvedBy: outcome.approvedBy,
      agentIdSource: pending?.agentIdSource,
    });
  }

  options.onDecision?.(info);

  if (finalDecision === 'deny') {
    throw new ToolGovernDenialError(info);
  }

  const ruleContext: RuleContext = {
    agentId: info.agentId,
    sessionId: info.sessionId,
    coordinatorId: info.coordinatorId,
    tool: info.tool,
    args: effectiveArgs,
    scope,
  };

  try {
    const result = await tool.execute(effectiveArgs);
    return options.onToolResult ? (options.onToolResult(result, ruleContext) as Result) : result;
  } catch (error) {
    if (options.onToolResult) {
      return options.onToolResult(error, ruleContext) as Result;
    }
    throw error;
  }
}
