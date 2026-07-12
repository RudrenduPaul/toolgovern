/**
 * Shared types for the toolgovern middleware, classifier, scoping, and trace modules.
 *
 * A gate decision is always one of three values -- there is no fourth "warn and continue"
 * state, because a warning that does not block execution is not governance, it is a log line.
 */

export type Decision = 'allow' | 'deny' | 'require-approval';

/**
 * Where an `agentId` came from when a gate decision was made: `'explicit'` means the caller
 * passed `options.agentId` to `governTool()` directly; `'fallback'` means no `agentId` was
 * supplied and toolgovern used its default (`'default-agent'`). This is provenance, not proof --
 * an `'explicit'` value is still just whatever string the caller happened to pass. toolgovern does
 * not cryptographically verify that a caller actually is the agent it claims to be (see
 * `docs/security-model.md`, "Agent identity is caller-asserted, not cryptographically verified").
 * Recording the source at least tells an auditor whether a decision was made against a
 * caller-asserted identity or a fallback default, which is the honest scope of what this field
 * gives you.
 */
export type AgentIdSource = 'explicit' | 'fallback';

/** The five v0.1 risk-rule categories. TG06/TG07 need cross-call session state and ship later. */
export type RuleCategory = 'TG01' | 'TG02' | 'TG03' | 'TG04' | 'TG05';

/**
 * A per-agent declared scope. `network` is either `false` (no network access at all), `true`
 * (unrestricted -- discouraged, but supported for local/dev use), or an explicit allowlist of
 * hostnames. `filesystem` is a list of path prefixes the agent may read/write/delete under.
 * `credentials` is a list of credential identifiers (file paths, secret names) the agent may
 * access.
 */
export interface ScopeDeclaration {
  readonly network: boolean | readonly string[];
  readonly filesystem: readonly string[];
  readonly credentials: readonly string[];
}

/** Rule-level overrides a policy file can apply on top of the shipped rule pack defaults. */
export interface RuleOverrides {
  /** Rule IDs to skip entirely -- the rule never fires, no matter the arguments. */
  readonly disable?: readonly string[];
  /** Rule IDs whose default `deny` decision should be downgraded to `require-approval`. */
  readonly requireApproval?: readonly string[];
}

/**
 * A loaded (or inline) policy. `loadPolicy()` returns this shape directly from a YAML file, and
 * `governTool()` accepts it as-is for its second argument -- so a policy loaded from disk and an
 * inline options object are the exact same type, which keeps the "wrap a tool" call site small.
 */
export interface Policy {
  /** Free-form policy label, e.g. `'strict-shell'`. Not used for rule matching, only for trace/UX. */
  readonly policy?: string;
  /** The policy file's declared name, when loaded from YAML via `name:`. */
  readonly name?: string;
  readonly scope: ScopeDeclaration;
  readonly rules?: RuleOverrides;
  /** Decision to use when no rule fires. Defaults to `'allow'`. */
  readonly defaultDecision?: Decision;
  readonly agentId?: string;
  readonly sessionId?: string;
  readonly coordinatorId?: string;
}

/**
 * What the scoping registry recorded for one agent: the scope it requested at spawn time (only
 * meaningful for sub-agents) and the scope actually granted after default-deny inheritance was
 * applied against its coordinator's own scope.
 */
export interface AgentScopeRecord {
  readonly agentId: string;
  readonly sessionId: string;
  readonly coordinatorId?: string;
  readonly requestedScope?: ScopeDeclaration;
  readonly grantedScope: ScopeDeclaration;
}

/** The minimal read surface TG05 needs from the scoping registry, kept here to avoid a
 *  classifier -> scoping import cycle; `ScopeRegistry` in `scoping/` implements this. */
export interface ScopeRegistryReader {
  getRecord(agentId: string): AgentScopeRecord | undefined;
}

/** The normalized input every classifier rule evaluates against. */
export interface RuleContext {
  readonly agentId: string;
  readonly sessionId: string;
  readonly coordinatorId?: string;
  readonly tool: string;
  readonly args: Readonly<Record<string, unknown>>;
  readonly scope: ScopeDeclaration;
  /** Present only when the caller wired a `ScopeRegistry` into `classify()`; used by TG05. */
  readonly scopeRegistry?: ScopeRegistryReader;
}

/** A single fired rule's result. `decision` is never `'allow'` -- a rule either fires or it doesn't. */
export interface RuleMatch {
  readonly ruleId: string;
  readonly category: RuleCategory;
  readonly decision: Exclude<Decision, 'allow'>;
  readonly reason: string;
  readonly matchedArgument?: string;
}

/** A classifier rule: pure function from call context to an optional match. */
export interface Rule {
  readonly id: string;
  readonly category: RuleCategory;
  readonly description: string;
  evaluate(ctx: RuleContext): RuleMatch | null;
}

/** The classifier's aggregate verdict for one tool call. */
export interface ClassifierResult {
  readonly decision: Decision;
  readonly firedRules: readonly RuleMatch[];
}

/** What the caller supplies to `TraceWriter#append()` for one gate decision. */
export interface TraceEntryInput {
  readonly sessionId: string;
  readonly agentId: string;
  readonly tool: string;
  readonly args: Readonly<Record<string, unknown>>;
  readonly decision: Decision;
  /** Rule IDs that fired for this call. Empty for a clean `allow`. */
  readonly ruleFired: readonly string[];
  readonly declaredScope: ScopeDeclaration;
  /** How `agentId` was resolved for this call (`'explicit'` vs. `'fallback'`). Optional so direct
   *  `TraceWriter.append()` callers that predate this field (or that have no source to report)
   *  are unaffected; `governTool()` always supplies it. See `AgentIdSource`. */
  readonly agentIdSource?: AgentIdSource;
}

/**
 * One append-only, signed trace record. `signature` is either `sha256:<hex>` (an unkeyed content
 * hash of everything except `signature` itself -- the default) or `hmac-sha256:<hex>` (a keyed
 * signature, when `TraceWriter` is given a `secretKey`; see `TraceWriterOptions`). `prior_trace_id`
 * chains this entry to the one before it in the same session -- together these let a reader detect
 * a missing, reordered, or tampered entry. The unkeyed form does not require managing a signing
 * key, but it also does not authenticate who wrote an entry, and does not stop an attacker with
 * write access to the trace file from editing an entry and recomputing a signature that still
 * verifies -- see `docs/security-model.md`.
 */
export interface TraceEntry {
  readonly trace_id: string;
  readonly timestamp: string;
  readonly session_id: string;
  readonly agent_id: string;
  readonly tool: string;
  readonly arguments_hash: string;
  readonly decision: Decision;
  readonly rule_fired: readonly string[];
  readonly declared_scope: ScopeDeclaration;
  /** How `agent_id` was resolved for this call -- see `AgentIdSource`. Optional for the same
   *  backward-compatibility reason as `TraceEntryInput.agentIdSource`; entries written before this
   *  field existed, or by a direct `TraceWriter.append()` caller that did not supply it, simply
   *  omit it rather than carrying a fabricated value. */
  readonly agent_id_source?: AgentIdSource;
  readonly signature: string;
  readonly prior_trace_id: string | null;
}
