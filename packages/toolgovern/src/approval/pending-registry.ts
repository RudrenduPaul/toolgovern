/**
 * `PendingApprovalRegistry` -- a durable, keyed record of `require-approval` gate decisions that
 * outlives a single in-process, 30-second `onApprovalRequired` callback.
 *
 * Today's `governTool()` treats a `require-approval` decision as something that must be answered
 * synchronously, in-process, before its own `execute()` promise settles (see `onToolCall.ts`).
 * That is a real, useful default, and this registry does not remove it -- it adds a second,
 * independent path: every `require-approval` decision is also persisted here as a
 * `PendingApproval`, keyed by a server-generated `pendingId`, so a caller who is NOT the original
 * in-process handler -- a webhook receiving a Slack button click, a CLI command, a long-running
 * human review queue polling for pending items -- can look it up and resolve it later, on its own
 * schedule, via `resolvePending()`.
 *
 * Three design decisions here are load-bearing, each anchored to a real shipped bug or finding:
 *
 * 1. **`pendingId` is always server-generated, never caller-supplied.** `registerPending()`
 *    mints the ID and hands it back; there is no way to register (or resolve) a pending approval
 *    under an ID the caller chose. This directly closes the bypass Corridor's security bot found
 *    in langchain-ai/langgraph#8169's `human_approval()` helper: that implementation read its
 *    resume token (`resume_command_id`) out of the *untrusted resume payload* and, when the ID
 *    was unrecognized, silently created a brand-new pending decision for it instead of failing
 *    closed -- so a caller who could resume an interrupted graph could mint a fresh ID and turn
 *    an expired/cancelled/mismatched approval into an approvable one. `resolvePending()` below
 *    never creates an entry for an unrecognized ID; an unknown `pendingId` is `'not-found'`,
 *    full stop -- see the test `resolvePending never creates a new pending approval for an
 *    unrecognized id (langgraph#8169 bypass)`.
 *
 * 2. **Alias tolerance for the same pending approval.** `registerAlias()` lets a caller record
 *    that some other identifier (a rewritten thread ID, a provider-issued conversation ID) now
 *    also refers to an already-registered `pendingId`; `get()` and `resolvePending()` accept
 *    either the original ID or any registered alias. This models the fix in
 *    microsoft/agent-framework#6908 ("Python: Fix AG-UI approval thread aliases"): a stateful
 *    provider (Foundry) streamed back a new conversation ID mid-thread, and the approval had been
 *    registered only under the original client thread ID, so a client resuming with that original
 *    ID could never find its own pending approval. That PR's fix -- and this registry's -- is to
 *    register the approval under every ID a caller has seen for the same logical thread, sharing
 *    one entry, so a resolve-by-any-alias consumes the same entry and a second resolve (by the
 *    same or a different alias) hits `'already-resolved'`, never a silent re-grant.
 *
 * 3. **Edited arguments are re-classified, never smuggled through on the strength of the
 *    original approval.** `resolvePending()` accepts `editedArgs`; when supplied alongside an
 *    `'allow'` decision, the edited arguments are run back through the classifier (the same
 *    `classifyAsync()` used by `governTool()`, with the same rule overrides that were active at
 *    registration time) before the resolution is accepted. A re-classification that still comes
 *    back non-`allow` overrides the human's `'allow'` -- approving a call is not a license to
 *    edit its arguments into something riskier and have that edit wave through unchecked. See
 *    `pending-registry.test.ts`, "denies edited args that would themselves trigger a deny, even
 *    after approval".
 *
 * What this registry deliberately does NOT do: it does not itself execute a tool, and it does
 * not itself write to a `TraceWriter`. It is a pure state machine over pending approvals.
 * `resumePendingApproval()` in `middleware/onToolCall.ts` is the piece that actually closes the
 * loop -- taking a resolved outcome from this registry and using it to run the real tool and
 * append one trace entry, with `approvedBy` populated exactly as the synchronous path does.
 *
 * This is also, by construction, in-memory only: a plain `Map`, scoped to one process. A
 * production deployment that needs the pending-approval record to survive a process restart, or
 * to be resolved from a different process than the one that registered it (the webhook case this
 * whole feature is aimed at), must back this with real durable storage (a database row, a Redis
 * key) behind the same interface -- that persistence layer is out of scope for this pass. See the
 * final report for exactly which upstream issues this narrows vs. fully closes.
 */

import { randomUUID } from 'node:crypto';
import { classifyAsync, type ClassifyOptions } from '../classifier/index.js';
import type {
  AgentIdSource,
  ClassifierResult,
  Decision,
  RuleContext,
  RuleMatch,
  ScopeDeclaration,
} from '../types.js';

/** The two terminal decisions a pending approval can be resolved to. `require-approval` is never
 *  a valid resolution -- something either ends up allowed or denied. */
export type ApprovalResolutionDecision = Extract<Decision, 'allow' | 'deny'>;

/** What `governTool()` (or any other caller) supplies to persist one `require-approval` gate
 *  decision as a durable, resumable record. */
export interface PendingApprovalDetails {
  readonly agentId: string;
  readonly sessionId: string;
  readonly coordinatorId?: string;
  readonly tool: string;
  readonly args: Readonly<Record<string, unknown>>;
  readonly scope: ScopeDeclaration;
  /** The classifier's fired rules for the *original* call -- kept for audit context even after
   *  `editedArgs` triggers a fresh re-classification at resolve time. */
  readonly firedRules: readonly RuleMatch[];
  readonly agentIdSource?: AgentIdSource;
  /** The same `Policy.rules.disable` list active when this call was classified -- captured so a
   *  later `resolvePending({ editedArgs })` re-classification applies the identical overrides,
   *  not some different default. */
  readonly disabledRules?: readonly string[];
  /** The same `Policy.rules.requireApproval` list active when this call was classified. */
  readonly downgradeToApproval?: readonly string[];
  /** How long this pending approval stays resolvable, in milliseconds from registration.
   *  Omitted (the default) means it never expires on its own -- it is still only ever resolvable
   *  once. */
  readonly ttlMs?: number;
}

export type PendingApprovalStatus = 'pending' | 'resolved' | 'expired';

/** What a resolved pending approval recorded about its own resolution. */
export interface PendingApprovalResolution {
  readonly decision: ApprovalResolutionDecision;
  readonly approvedBy?: string;
  readonly resolvedAt: number;
  readonly editedArgs?: Readonly<Record<string, unknown>>;
  /** Present only when `editedArgs` was supplied and actually re-classified. */
  readonly reclassified?: ClassifierResult;
}

/** The public, read-only view of one registered pending approval, as returned by `get()`. */
export interface PendingApproval {
  readonly pendingId: string;
  readonly agentId: string;
  readonly sessionId: string;
  readonly coordinatorId?: string;
  readonly tool: string;
  readonly args: Readonly<Record<string, unknown>>;
  readonly scope: ScopeDeclaration;
  readonly firedRules: readonly RuleMatch[];
  readonly agentIdSource?: AgentIdSource;
  readonly status: PendingApprovalStatus;
  readonly createdAt: number;
  readonly expiresAt?: number;
  /** Every alias currently resolving to this same entry, in registration order. Does not include
   *  `pendingId` itself. */
  readonly aliases: readonly string[];
  readonly resolution?: PendingApprovalResolution;
}

export interface ResolvePendingInput {
  readonly decision: ApprovalResolutionDecision;
  readonly approvedBy?: string;
  /** Edited arguments to approve/deny instead of the originally registered `args`. When present
   *  together with `decision: 'allow'`, the edited arguments are re-run through the classifier
   *  before the resolution is accepted -- see the module doc comment, point 3. */
  readonly editedArgs?: Readonly<Record<string, unknown>>;
}

export type ResolvePendingStatus = 'resolved' | 'not-found' | 'already-resolved' | 'expired';

export interface ResolvePendingOutcome {
  readonly status: ResolvePendingStatus;
  /** Echoes back whatever ID/alias the caller resolved with -- NOT necessarily the canonical
   *  `pendingId`, when `status` is `'not-found'` (there is no canonical id to report). */
  readonly pendingId: string;
  /** The decision actually in effect: `input.decision`, unless `editedArgs` re-classification
   *  overrode an `'allow'` down to `'deny'`. Present only for `'resolved'` and
   *  `'already-resolved'` (the latter echoes the *first* resolution's outcome, never a second
   *  one -- there is no second one). */
  readonly finalDecision?: ApprovalResolutionDecision;
  readonly approvedBy?: string;
  /** The arguments actually approved/denied: `editedArgs` when supplied, the originally
   *  registered `args` otherwise. Present for the same statuses as `finalDecision`. */
  readonly args?: Readonly<Record<string, unknown>>;
  /** Only present when `editedArgs` was supplied and actually re-classified -- the fresh rule
   *  matches from that re-classification, not the original call's `firedRules`. */
  readonly firedRules?: readonly RuleMatch[];
}

/** Raised by `registerAlias()` when asked to alias an ID/alias with no registered entry. An
 *  alias must always point at a real, already-registered pending approval -- silently accepting
 *  one for an unknown ID would let a caller plant a phantom entry that later resolves as if it
 *  had gone through the classifier, which it never did. */
export class UnknownPendingApprovalError extends Error {
  constructor(public readonly pendingId: string) {
    super(
      `toolgovern: no pending approval is registered under id/alias ${JSON.stringify(pendingId)}.`,
    );
    this.name = 'UnknownPendingApprovalError';
  }
}

/** Raised by `registerAlias()` when `alias` already refers to a *different* pending approval than
 *  the one being aliased -- silently repointing it would let a second, unrelated call's
 *  resolution land on the first call's entry. */
export class PendingApprovalAliasConflictError extends Error {
  constructor(public readonly alias: string) {
    super(
      `toolgovern: alias ${JSON.stringify(alias)} already refers to a different pending approval.`,
    );
    this.name = 'PendingApprovalAliasConflictError';
  }
}

interface PendingApprovalEntry {
  readonly pendingId: string;
  readonly agentId: string;
  readonly sessionId: string;
  readonly coordinatorId?: string;
  readonly tool: string;
  readonly args: Readonly<Record<string, unknown>>;
  readonly scope: ScopeDeclaration;
  readonly firedRules: readonly RuleMatch[];
  readonly agentIdSource?: AgentIdSource;
  readonly disabledRules: readonly string[];
  readonly downgradeToApproval: readonly string[];
  readonly createdAt: number;
  readonly expiresAt?: number;
  readonly aliases: Set<string>;
  status: PendingApprovalStatus;
  resolution?: PendingApprovalResolution;
}

export interface PendingApprovalRegistryOptions {
  /** Injectable clock, purely for deterministic tests of `ttlMs` expiry. Defaults to `Date.now`. */
  readonly now?: () => number;
  /** Injectable ID generator, purely for deterministic tests. Defaults to `crypto.randomUUID`. */
  readonly idFactory?: () => string;
  /** Injectable re-classification function -- defaults to the real `classifyAsync()`. Overriding
   *  this is for tests only; production callers should never need to. */
  readonly reclassify?: (ctx: RuleContext, options: ClassifyOptions) => Promise<ClassifierResult>;
}

/**
 * A keyed, in-memory registry of pending `require-approval` gate decisions. See the module doc
 * comment above for the three bug-shaped design decisions this embodies.
 */
export class PendingApprovalRegistry {
  private readonly entries = new Map<string, PendingApprovalEntry>();
  /** alias -> canonical pendingId. A canonical `pendingId` is never itself a key in this map --
   *  `resolveCanonicalId()` checks `entries` first, so a real ID always wins over any alias. */
  private readonly aliasToCanonical = new Map<string, string>();

  private readonly now: () => number;
  private readonly idFactory: () => string;
  private readonly reclassify: (
    ctx: RuleContext,
    options: ClassifyOptions,
  ) => Promise<ClassifierResult>;

  constructor(options: PendingApprovalRegistryOptions = {}) {
    this.now = options.now ?? Date.now;
    this.idFactory = options.idFactory ?? randomUUID;
    this.reclassify = options.reclassify ?? classifyAsync;
  }

  /** Persists one `require-approval` gate decision and returns its server-generated `pendingId`.
   *  The caller never supplies (and cannot influence) this ID -- see the module doc comment,
   *  point 1. */
  registerPending(details: PendingApprovalDetails): string {
    const pendingId = this.idFactory();
    const createdAt = this.now();
    const entry: PendingApprovalEntry = {
      pendingId,
      agentId: details.agentId,
      sessionId: details.sessionId,
      coordinatorId: details.coordinatorId,
      tool: details.tool,
      args: details.args,
      scope: details.scope,
      firedRules: details.firedRules,
      agentIdSource: details.agentIdSource,
      disabledRules: details.disabledRules ?? [],
      downgradeToApproval: details.downgradeToApproval ?? [],
      createdAt,
      expiresAt: details.ttlMs !== undefined ? createdAt + details.ttlMs : undefined,
      aliases: new Set(),
      status: 'pending',
    };
    this.entries.set(pendingId, entry);
    return pendingId;
  }

  /** Records that `alias` now also refers to the pending approval registered under `pendingId`
   *  (which may itself already be an alias). Resolving by `pendingId` OR `alias` afterward
   *  reaches the same entry. See the module doc comment, point 2 (microsoft/agent-framework
   *  #6908's thread-id-rewrite bug). */
  registerAlias(pendingId: string, alias: string): void {
    const canonical = this.resolveCanonicalId(pendingId);
    if (!canonical) {
      throw new UnknownPendingApprovalError(pendingId);
    }
    const existingTarget = this.resolveCanonicalId(alias);
    if (existingTarget && existingTarget !== canonical) {
      throw new PendingApprovalAliasConflictError(alias);
    }
    this.entries.get(canonical)!.aliases.add(alias);
    this.aliasToCanonical.set(alias, canonical);
  }

  /** Looks up a pending approval by its `pendingId` OR any registered alias. Returns `undefined`
   *  for anything unrecognized -- never fabricates an entry. */
  get(pendingIdOrAlias: string): PendingApproval | undefined {
    const canonical = this.resolveCanonicalId(pendingIdOrAlias);
    if (!canonical) return undefined;
    const entry = this.entries.get(canonical);
    return entry ? this.toPublic(entry) : undefined;
  }

  /**
   * Resolves a pending approval, by `pendingId` or any registered alias, to a terminal decision.
   *
   * - An unrecognized `pendingIdOrAlias` returns `{ status: 'not-found' }` -- it is NEVER treated
   *   as a fresh grant to be created on the spot. See the module doc comment, point 1
   *   (langchain-ai/langgraph#8169's resume-token bypass).
   * - An already-resolved entry returns `{ status: 'already-resolved' }` with the *original*
   *   resolution's outcome -- resolving twice (by the same id or a different alias of the same
   *   entry) can never flip a decision or re-trigger execution. This is also what makes alias
   *   resolution replay-safe: consuming any one alias consumes the shared entry for all of them.
   * - An expired entry (past `ttlMs`) returns `{ status: 'expired' }` and is marked `'expired'`,
   *   never resolvable afterward.
   * - Otherwise, the entry is resolved. If `editedArgs` is supplied together with
   *   `decision: 'allow'`, the edited arguments are re-run through the classifier (the same rule
   *   overrides captured at registration time); any result other than `'allow'` overrides the
   *   human's `'allow'` down to `'deny'` -- see the module doc comment, point 3.
   */
  async resolvePending(
    pendingIdOrAlias: string,
    input: ResolvePendingInput,
  ): Promise<ResolvePendingOutcome> {
    const canonical = this.resolveCanonicalId(pendingIdOrAlias);
    if (!canonical) {
      return { status: 'not-found', pendingId: pendingIdOrAlias };
    }
    const entry = this.entries.get(canonical)!;

    if (
      entry.status === 'expired' ||
      (entry.expiresAt !== undefined && this.now() > entry.expiresAt)
    ) {
      entry.status = 'expired';
      return { status: 'expired', pendingId: canonical };
    }

    if (entry.status === 'resolved') {
      const resolution = entry.resolution!;
      return {
        status: 'already-resolved',
        pendingId: canonical,
        finalDecision: resolution.decision,
        approvedBy: resolution.approvedBy,
        args: resolution.editedArgs ?? entry.args,
        firedRules: resolution.reclassified?.firedRules,
      };
    }

    const effectiveArgs = input.editedArgs ?? entry.args;
    let finalDecision: ApprovalResolutionDecision = input.decision;
    let reclassified: ClassifierResult | undefined;

    if (input.editedArgs !== undefined && input.decision === 'allow') {
      // Approving an edit is never itself a bypass -- the edited arguments must clear the same
      // classifier a fresh call would. Anything other than a clean `allow` here (including a
      // fresh `require-approval`, which this single resolve step cannot itself re-adjudicate)
      // overrides the human's decision down to `deny`, fail-closed.
      const ctx: RuleContext = {
        agentId: entry.agentId,
        sessionId: entry.sessionId,
        coordinatorId: entry.coordinatorId,
        tool: entry.tool,
        args: input.editedArgs,
        scope: entry.scope,
      };
      reclassified = await this.reclassify(ctx, {
        disabledRules: entry.disabledRules,
        downgradeToApproval: entry.downgradeToApproval,
      });
      if (reclassified.decision !== 'allow') {
        finalDecision = 'deny';
      }
    }

    entry.status = 'resolved';
    entry.resolution = {
      decision: finalDecision,
      approvedBy: input.approvedBy,
      resolvedAt: this.now(),
      editedArgs: input.editedArgs,
      reclassified,
    };

    return {
      status: 'resolved',
      pendingId: canonical,
      finalDecision,
      approvedBy: input.approvedBy,
      args: effectiveArgs,
      firedRules: reclassified?.firedRules,
    };
  }

  private resolveCanonicalId(idOrAlias: string): string | undefined {
    if (this.entries.has(idOrAlias)) return idOrAlias;
    return this.aliasToCanonical.get(idOrAlias);
  }

  private toPublic(entry: PendingApprovalEntry): PendingApproval {
    return {
      pendingId: entry.pendingId,
      agentId: entry.agentId,
      sessionId: entry.sessionId,
      coordinatorId: entry.coordinatorId,
      tool: entry.tool,
      args: entry.args,
      scope: entry.scope,
      firedRules: entry.firedRules,
      agentIdSource: entry.agentIdSource,
      status: entry.status,
      createdAt: entry.createdAt,
      expiresAt: entry.expiresAt,
      aliases: [...entry.aliases],
      resolution: entry.resolution,
    };
  }
}
