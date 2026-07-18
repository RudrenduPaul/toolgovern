using ToolGovern.Approval;
using ToolGovern.Classifier;
using ToolGovern.Scoping;
using ToolGovern.Trace;

namespace ToolGovern.Middleware;

/// <summary>
/// A tool definition: a name plus an execute function. Args are fixed to
/// <c>IReadOnlyDictionary&lt;string, object?&gt;</c> -- the same shape <see cref="RuleContext"/>
/// evaluates against -- mirroring the TypeScript original's <c>Record&lt;string, unknown&gt;</c>
/// constraint on <c>ToolDefinition&lt;Args, Result&gt;</c>.
/// </summary>
public sealed class ToolDefinition<TResult>
{
    public required string Name { get; init; }
    public required Func<IReadOnlyDictionary<string, object?>, Task<TResult>> Execute { get; init; }
}

/// <summary>Everything surfaced to OnApprovalRequired and OnDecision about one gate decision.</summary>
public sealed class GateDecisionInfo
{
    public required string AgentId { get; init; }
    public required string SessionId { get; init; }
    public string? CoordinatorId { get; init; }
    public required string Tool { get; init; }
    public required IReadOnlyDictionary<string, object?> Args { get; init; }
    public required Decision Decision { get; init; }
    public required IReadOnlyList<RuleMatch> FiredRules { get; init; }
    public required ScopeDeclaration Scope { get; init; }
    /// <summary>The durable PendingApprovalRegistry id for this decision, when
    /// options.PendingApprovals was supplied and this decision was RequireApproval.</summary>
    public string? PendingId { get; init; }
}

/// <summary>What an ApprovalHandler resolves to: whether the call was approved, and optionally
/// who approved/denied it.</summary>
public sealed class ApprovalOutcome
{
    public required bool Approved { get; init; }
    /// <summary>Identity of the human who approved or denied the call. Recorded on the trace
    /// entry as ApprovedBy when present.</summary>
    public string? ApprovedBy { get; init; }
}

/// <summary>Called only for RequireApproval decisions. Return Approved = true to allow the call
/// through, false to deny it. A null handler (the default) means every RequireApproval decision
/// is denied (fail-closed) -- there is no such thing as an implicit approval.</summary>
public delegate Task<ApprovalOutcome> ApprovalHandler(GateDecisionInfo info);

/// <summary>Options accepted by GovernTool(), extending Policy with runtime wiring.</summary>
public sealed class GovernToolOptions : Policy
{
    public ScopeRegistry? ScopeRegistry { get; init; }
    public TraceWriter? Trace { get; init; }
    public ApprovalHandler? OnApprovalRequired { get; init; }
    /// <summary>How long to wait for OnApprovalRequired before treating it as a denial. Defaults
    /// to 30s.</summary>
    public double ApprovalTimeoutMs { get; init; } = 30_000;
    /// <summary>Optional durable registry for RequireApproval decisions.</summary>
    public PendingApprovalRegistry? PendingApprovals { get; init; }
    /// <summary>Fires after every gate decision, allow/deny/require-approval alike, after the
    /// trace entry (if any) has been written.</summary>
    public Action<GateDecisionInfo>? OnDecision { get; init; }
    /// <summary>Optional post-execution hook. Once a call is allowed and tool.Execute() has run
    /// (or thrown), the raw result -- or the thrown exception -- is passed through this function
    /// before anything is returned to the caller.</summary>
    public Func<object?, RuleContext, object?>? OnToolResult { get; init; }
    /// <summary>Optional in-memory retry dedup for tools with real-world side effects.</summary>
    public IdempotencyOptions? Idempotency { get; init; }
}

public sealed class ToolGovernDenialError : Exception
{
    public GateDecisionInfo DecisionInfo { get; }

    public ToolGovernDenialError(GateDecisionInfo decisionInfo) : base(BuildMessage(decisionInfo))
    {
        DecisionInfo = decisionInfo;
    }

    private static string BuildMessage(GateDecisionInfo info)
    {
        var ruleIds = info.FiredRules.Count > 0 ? string.Join(", ", info.FiredRules.Select(r => r.RuleId)) : "policy default";
        return $"toolgovern denied tool call \"{info.Tool}\" (agent \"{info.AgentId}\"): {ruleIds}";
    }
}

/// <summary>
/// Thrown by GovernTool() when an explicitly-supplied AgentId fails the format check in
/// ScopeDeclarationHelpers.IsValidAgentId (empty, excessively long, or containing
/// control/injection-style characters). This is a format rejection, not an identity-verification
/// failure.
/// </summary>
public sealed class InvalidAgentIdException : Exception
{
    public string RawAgentId { get; }

    public InvalidAgentIdException(string rawAgentId) : base(
        $"toolgovern rejected a malformed agentId: \"{rawAgentId}\". It must be a non-empty string, " +
        "no longer than 256 characters, with no control characters. This is a format check only -- " +
        "it does not verify the caller actually is the agent it claims to be.")
    {
        RawAgentId = rawAgentId;
    }
}

internal static class ApprovalResolver
{
    public static async Task<(ApprovalOutcome Outcome, bool Answered)> ResolveApproval(
        ApprovalHandler? handler, GateDecisionInfo info, double timeoutMs)
    {
        if (handler is null) return (new ApprovalOutcome { Approved = false }, false);

        async Task<(ApprovalOutcome, bool)> InvokeSafely()
        {
            try
            {
                var outcome = await handler(info);
                return (outcome, true);
            }
            catch
            {
                // A handler that throws (sync or async) must fail closed exactly like "no
                // handler" or "timed out" -- it must NOT propagate out of GovernTool().
                return (new ApprovalOutcome { Approved = false }, false);
            }
        }

        var handlerTask = InvokeSafely();
        var timeoutTask = Task.Delay(TimeSpan.FromMilliseconds(timeoutMs))
            .ContinueWith(_ => (new ApprovalOutcome { Approved = false }, false), TaskScheduler.Default);

        var completed = await Task.WhenAny(handlerTask, timeoutTask);
        return await completed;
    }
}

/// <summary>
/// GovernTool() -- the core hook. Wraps any tool definition a framework already has and returns a
/// version that evaluates every invocation through the classifier before the underlying tool
/// executes. A gated call never reaches the real tool implementation until the classifier's
/// decision resolves to Allow. Deny throws ToolGovernDenialError without executing the tool at
/// all. RequireApproval calls OnApprovalRequired if one was provided; with no handler, or if the
/// handler times out, the call fails closed (denied).
/// </summary>
public static class ToolGovernMiddleware
{
    private static ScopeDeclaration ResolveEffectiveScope(GovernToolOptions options, string agentId, string sessionId)
    {
        var scopeRegistry = options.ScopeRegistry;
        if (scopeRegistry is null) return options.Scope;

        var existing = scopeRegistry.GetRecord(agentId);
        if (existing is not null) return existing.GrantedScope;

        if (options.CoordinatorId is not null)
        {
            return scopeRegistry.SpawnSubAgent(new SpawnSubAgentParams
            {
                CoordinatorId = options.CoordinatorId,
                SubAgentId = agentId,
                SessionId = sessionId,
                RequestedScope = options.Scope,
            }).GrantedScope;
        }
        return scopeRegistry.RegisterRootAgent(agentId, sessionId, options.Scope).GrantedScope;
    }

    /// <summary>
    /// Wraps tool so every call is evaluated by the classifier before it executes. options is a
    /// Policy (whether hand-written inline or loaded from YAML) plus optional runtime wiring.
    /// </summary>
    public static ToolDefinition<TResult> GovernTool<TResult>(ToolDefinition<TResult> tool, GovernToolOptions options)
    {
        // AgentId is a caller-asserted string, never cryptographically verified. What we CAN do
        // here is reject a malformed one outright, and record whether this call's AgentId was
        // explicitly supplied or fell back to the default.
        if (options.AgentId is not null && !ScopeDeclarationHelpers.IsValidAgentId(options.AgentId))
        {
            throw new InvalidAgentIdException(options.AgentId);
        }
        var agentIdSource = options.AgentId is not null ? AgentIdSource.Explicit : AgentIdSource.Fallback;
        var agentId = options.AgentId ?? "default-agent";
        var sessionId = options.SessionId ?? "default-session";
        var coordinatorId = options.CoordinatorId;
        var disabledRules = options.Rules?.Disable ?? [];
        var downgradeToApproval = options.Rules?.RequireApproval ?? [];
        var defaultDecision = options.DefaultDecision;
        var approvalTimeoutMs = options.ApprovalTimeoutMs;
        // Scoped to this one gated tool instance -- never shared globally across every gate in a
        // process.
        var idempotencyCache = options.Idempotency?.Enabled == true
            ? new IdempotencyCache<TResult>(options.Idempotency.TtlMs)
            : null;

        async Task<TResult> Execute(IReadOnlyDictionary<string, object?> args)
        {
            var effectiveScope = ResolveEffectiveScope(options, agentId, sessionId);

            var ruleContext = new RuleContext
            {
                AgentId = agentId,
                SessionId = sessionId,
                CoordinatorId = coordinatorId,
                Tool = tool.Name,
                Args = args,
                Scope = effectiveScope,
                ScopeRegistry = options.ScopeRegistry,
            };

            // ClassifyAsync (not the synchronous Classify()) so TG03's DNS-resolution check
            // actually runs -- Execute() is already async end-to-end.
            var classifierResult = await ClassifierEngine.ClassifyAsync(ruleContext, new ClassifierEngine.ClassifyOptions
            {
                DisabledRules = disabledRules,
                DowngradeToApproval = downgradeToApproval,
            });
            var decision = classifierResult.Decision;
            var firedRules = classifierResult.FiredRules;

            // A defaultDecision other than Allow only applies when the classifier found nothing
            // to flag -- it never overrides an explicit rule verdict.
            if (firedRules.Count == 0 && defaultDecision != Decision.Allow)
            {
                decision = defaultDecision;
            }

            // Registered BEFORE OnApprovalRequired is invoked (or even looked at), so a durable
            // record of this decision exists regardless of whether the synchronous handler
            // answers, times out, throws, or was never provided at all.
            string? pendingId = null;
            if (decision == Decision.RequireApproval && options.PendingApprovals is not null)
            {
                pendingId = options.PendingApprovals.RegisterPending(new PendingApprovalDetails
                {
                    AgentId = agentId,
                    SessionId = sessionId,
                    CoordinatorId = coordinatorId,
                    Tool = tool.Name,
                    Args = args,
                    Scope = effectiveScope,
                    FiredRules = firedRules,
                    AgentIdSource = agentIdSource,
                    DisabledRules = disabledRules,
                    DowngradeToApproval = downgradeToApproval,
                });
            }

            var info = new GateDecisionInfo
            {
                AgentId = agentId,
                SessionId = sessionId,
                CoordinatorId = coordinatorId,
                Tool = tool.Name,
                Args = args,
                Decision = decision,
                FiredRules = firedRules,
                Scope = effectiveScope,
                PendingId = pendingId,
            };

            var finalDecision = decision;
            string? approvedBy = null;
            if (decision == Decision.RequireApproval)
            {
                var (outcome, answered) = await ApprovalResolver.ResolveApproval(options.OnApprovalRequired, info, approvalTimeoutMs);
                finalDecision = outcome.Approved ? Decision.Allow : Decision.Deny;
                approvedBy = outcome.ApprovedBy;

                // Only reflect this outcome back into the durable registry when the synchronous
                // handler actually, genuinely answered -- a real decision, allow or deny, is
                // terminal. When nothing genuinely answered, this execute() call still fails
                // closed exactly as before -- but the registry entry is deliberately left pending.
                if (pendingId is not null && options.PendingApprovals is not null && answered)
                {
                    await options.PendingApprovals.ResolvePending(pendingId, new ResolvePendingInput
                    {
                        Decision = finalDecision,
                        ApprovedBy = approvedBy,
                    });
                }
            }

            if (options.Trace is not null)
            {
                var ruleFiredIds = firedRules.Count > 0
                    ? firedRules.Select(r => r.RuleId).ToList()
                    : finalDecision != Decision.Allow ? ["policy-default-decision"] : [];
                await options.Trace.Append(new TraceEntryInput
                {
                    SessionId = sessionId,
                    AgentId = agentId,
                    Tool = tool.Name,
                    Args = args,
                    Decision = finalDecision,
                    RuleFired = ruleFiredIds,
                    DeclaredScope = effectiveScope,
                    ApprovedBy = approvedBy,
                    AgentIdSource = agentIdSource,
                });
            }

            options.OnDecision?.Invoke(info);

            if (finalDecision == Decision.Deny)
            {
                throw new ToolGovernDenialError(info);
            }

            // A thrown/rejected Execute() (whether run directly or via the idempotency cache
            // below) is caught here rather than left to propagate directly, so OnToolResult (when
            // provided) gets a chance to see it before anything reaches the caller.
            try
            {
                var result = idempotencyCache is not null
                    ? await idempotencyCache.ClaimIfAbsent(IdempotencyCache<TResult>.KeyFor(tool.Name, args), () => tool.Execute(args))
                    : await tool.Execute(args);
                return options.OnToolResult is not null ? (TResult)options.OnToolResult(result, ruleContext)! : result;
            }
            catch (Exception error)
            {
                if (options.OnToolResult is not null)
                {
                    return (TResult)options.OnToolResult(error, ruleContext)!;
                }
                throw;
            }
        }

        return new ToolDefinition<TResult> { Name = tool.Name, Execute = Execute };
    }

    /// <summary>Raised by ResumePendingApproval() when the pendingId it was given cannot be
    /// resolved to a fresh, actionable decision.</summary>
    public sealed class PendingApprovalNotResolvableException : Exception
    {
        public string PendingId { get; }
        public ResolvePendingStatus Status { get; }

        public PendingApprovalNotResolvableException(string pendingId, ResolvePendingStatus status) : base(
            $"toolgovern: pending approval \"{pendingId}\" could not be resolved ({status}).")
        {
            PendingId = pendingId;
            Status = status;
        }
    }

    /// <summary>Optional wiring ResumePendingApproval() accepts -- the same shape of
    /// Trace/OnDecision/OnToolResult options GovernTool() itself accepts.</summary>
    public sealed class ResumePendingApprovalOptions
    {
        public TraceWriter? Trace { get; init; }
        public Action<GateDecisionInfo>? OnDecision { get; init; }
        public Func<object?, RuleContext, object?>? OnToolResult { get; init; }
    }

    /// <summary>
    /// Closes the loop PendingApprovals opens: given the SAME tool definition GovernTool() was
    /// originally wrapping, a PendingApprovalRegistry that call registered its RequireApproval
    /// decision in, the pendingId it was given back, and a resolution, this resolves the pending
    /// approval and -- if and only if the resolution (after any edited-args re-classification)
    /// comes back Allow -- actually invokes tool.Execute() with the effective arguments, appends
    /// one trace entry with ApprovedBy populated exactly as the synchronous path does, and returns
    /// the tool's result.
    /// </summary>
    public static async Task<TResult> ResumePendingApproval<TResult>(
        ToolDefinition<TResult> tool,
        PendingApprovalRegistry registry,
        string pendingId,
        ResolvePendingInput resolution,
        ResumePendingApprovalOptions? options = null)
    {
        options ??= new ResumePendingApprovalOptions();
        var pending = registry.Get(pendingId);
        var outcome = await registry.ResolvePending(pendingId, resolution);

        if (outcome.Status != ResolvePendingStatus.Resolved)
        {
            throw new PendingApprovalNotResolvableException(pendingId, outcome.Status);
        }

        var effectiveArgs = outcome.Args ?? pending?.Args ?? new Dictionary<string, object?>();
        var firedRules = outcome.FiredRules ?? pending?.FiredRules ?? [];
        var scope = pending?.Scope ?? new ScopeDeclaration { Network = NetworkScope.False, Filesystem = [], Credentials = [] };
        var finalDecision = outcome.FinalDecision == Decision.Allow ? Decision.Allow : Decision.Deny;

        var info = new GateDecisionInfo
        {
            AgentId = pending?.AgentId ?? "default-agent",
            SessionId = pending?.SessionId ?? "default-session",
            CoordinatorId = pending?.CoordinatorId,
            Tool = pending?.Tool ?? tool.Name,
            Args = effectiveArgs,
            Decision = finalDecision,
            FiredRules = firedRules,
            Scope = scope,
            PendingId = pendingId,
        };

        if (options.Trace is not null)
        {
            var ruleFiredIds = firedRules.Count > 0
                ? firedRules.Select(r => r.RuleId).ToList()
                : finalDecision != Decision.Allow ? ["policy-default-decision"] : [];
            await options.Trace.Append(new TraceEntryInput
            {
                SessionId = info.SessionId,
                AgentId = info.AgentId,
                Tool = info.Tool,
                Args = effectiveArgs,
                Decision = finalDecision,
                RuleFired = ruleFiredIds,
                DeclaredScope = scope,
                ApprovedBy = outcome.ApprovedBy,
                AgentIdSource = pending?.AgentIdSource,
            });
        }

        options.OnDecision?.Invoke(info);

        if (finalDecision == Decision.Deny)
        {
            throw new ToolGovernDenialError(info);
        }

        var ruleContext = new RuleContext
        {
            AgentId = info.AgentId,
            SessionId = info.SessionId,
            CoordinatorId = info.CoordinatorId,
            Tool = info.Tool,
            Args = effectiveArgs,
            Scope = scope,
        };

        try
        {
            var result = await tool.Execute(effectiveArgs);
            return options.OnToolResult is not null ? (TResult)options.OnToolResult(result, ruleContext)! : result;
        }
        catch (Exception error)
        {
            if (options.OnToolResult is not null)
            {
                return (TResult)options.OnToolResult(error, ruleContext)!;
            }
            throw;
        }
    }
}
