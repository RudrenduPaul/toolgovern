namespace ToolGovern.Classifier;

/// <summary>
/// The classifier: runs every rule in the TG01-TG05 + TG08 pack against one normalized call
/// context and aggregates the result. Decision severity order is Deny &gt; RequireApproval &gt;
/// Allow -- if any rule denies, the call is denied, no matter how many other rules would have
/// allowed it. Every non-allow decision is traceable to the specific rule ID(s) that fired.
/// </summary>
public static class ClassifierEngine
{
    public static readonly IReadOnlyList<IRule> RuleRegistry =
    [
        .. ShellRiskRules.Rules,
        .. FilesystemScopeRules.Rules,
        .. NetworkEgressRules.Rules,
        .. CredentialAccessRules.Rules,
        .. CrossAgentInheritanceRules.Rules,
        .. InformationFlowRules.Rules,
    ];

    /// <summary>Every registered async rule -- currently just TG03's DNS-resolution check.
    /// Evaluated only by ClassifyAsync(), never by the synchronous Classify().</summary>
    public static readonly IReadOnlyList<IAsyncRule> AsyncRuleRegistry = [.. NetworkEgressRules.AsyncRules];

    public sealed class ClassifyOptions
    {
        /// <summary>Rule IDs to skip entirely regardless of arguments (from Policy.Rules.Disable).</summary>
        public IReadOnlyList<string>? DisabledRules { get; init; }

        /// <summary>Rule IDs whose Deny verdict should be downgraded to RequireApproval (from
        /// Policy.Rules.RequireApproval).</summary>
        public IReadOnlyList<string>? DowngradeToApproval { get; init; }
    }

    private static int Severity(Decision decision) => decision switch
    {
        Decision.Deny => 2,
        Decision.RequireApproval => 1,
        _ => 0,
    };

    private static RuleMatch ApplyDowngrade(RuleMatch result, ISet<string> downgrade) =>
        result.Decision == Decision.Deny && downgrade.Contains(result.RuleId)
            ? result with { Decision = Decision.RequireApproval }
            : result;

    private static Decision AggregateDecision(IReadOnlyList<RuleMatch> firedRules)
    {
        var acc = Decision.Allow;
        foreach (var r in firedRules)
        {
            if (Severity(r.Decision) > Severity(acc)) acc = r.Decision;
        }
        return acc;
    }

    /// <summary>Evaluates one tool call against every enabled synchronous rule and returns the
    /// aggregate verdict. Does not run AsyncRuleRegistry (TG03's DNS-resolution check) -- a caller
    /// that can await should use ClassifyAsync() instead so that check is not silently skipped.</summary>
    public static ClassifierResult Classify(RuleContext ctx, ClassifyOptions? options = null)
    {
        options ??= new ClassifyOptions();
        var disabled = new HashSet<string>(options.DisabledRules ?? []);
        var downgrade = new HashSet<string>(options.DowngradeToApproval ?? []);

        var firedRules = new List<RuleMatch>();
        foreach (var rule in RuleRegistry)
        {
            if (disabled.Contains(rule.Id)) continue;
            var result = rule.Evaluate(ctx);
            if (result is null) continue;
            firedRules.Add(ApplyDowngrade(result, downgrade));
        }

        return new ClassifierResult(AggregateDecision(firedRules), firedRules);
    }

    /// <summary>
    /// Async counterpart to Classify(). Runs every synchronous rule exactly as Classify() does,
    /// then awaits every registered async rule (currently just TG03's DNS-resolution check) and
    /// folds its verdict into the same aggregate, at the same Deny &gt; RequireApproval &gt; Allow
    /// severity ordering. GovernTool()'s Execute() -- already async end-to-end -- calls this
    /// instead of Classify() so a hostname argument that resolves to a private/loopback/
    /// cloud-metadata address is caught, not just a raw IP literal argument.
    /// </summary>
    public static async Task<ClassifierResult> ClassifyAsync(RuleContext ctx, ClassifyOptions? options = null)
    {
        options ??= new ClassifyOptions();
        var disabled = new HashSet<string>(options.DisabledRules ?? []);
        var downgrade = new HashSet<string>(options.DowngradeToApproval ?? []);

        var firedRules = new List<RuleMatch>();
        foreach (var rule in RuleRegistry)
        {
            if (disabled.Contains(rule.Id)) continue;
            var result = rule.Evaluate(ctx);
            if (result is null) continue;
            firedRules.Add(ApplyDowngrade(result, downgrade));
        }

        foreach (var rule in AsyncRuleRegistry)
        {
            if (disabled.Contains(rule.Id)) continue;
            var result = await rule.EvaluateAsync(ctx);
            if (result is null) continue;
            firedRules.Add(ApplyDowngrade(result, downgrade));
        }

        return new ClassifierResult(AggregateDecision(firedRules), firedRules);
    }
}
