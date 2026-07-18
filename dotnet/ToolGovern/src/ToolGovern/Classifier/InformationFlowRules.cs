namespace ToolGovern.Classifier;

/// <summary>
/// TG08 -- Information-Flow Control (confidentiality-label propagation). A call reads from a
/// source labeled confidential-or-higher and writes/sends to a destination whose declared trust
/// tier is lower (or not declared at all). Fail-closed: an undeclared sink never silently allows.
/// </summary>
public static class InformationFlowRules
{
    private const string Category = "TG08";

    private static readonly ConfidentialityLabel[] LabelOrder =
    [
        ConfidentialityLabel.Public,
        ConfidentialityLabel.Internal,
        ConfidentialityLabel.Confidential,
        ConfidentialityLabel.Restricted,
    ];

    private static int LabelRank(ConfidentialityLabel label) => Array.IndexOf(LabelOrder, label);

    private static readonly string[] SourceKeys = ["source", "sourceId", "from", "readFrom"];
    private static readonly string[] SinkKeys = ["sink", "sinkId", "to", "destination", "sendTo", "forwardTo"];

    private static string? FirstString(IReadOnlyDictionary<string, object?> args, IReadOnlyList<string> keys)
    {
        foreach (var key in keys)
        {
            if (args.TryGetValue(key, out var value) && value is string s && s.Length > 0) return s;
        }
        return null;
    }

    /// <summary>Whether identifier matches an entry in a declared IfcPolicy label map -- exact
    /// match, a trailing path-segment match, or a substring match.</summary>
    private static ConfidentialityLabel? LookupLabel(string identifier, IReadOnlyDictionary<string, ConfidentialityLabel> labels)
    {
        var lower = identifier.ToLowerInvariant();
        foreach (var (key, label) in labels)
        {
            if (key.ToLowerInvariant() == lower) return label;
        }
        foreach (var (key, label) in labels)
        {
            var k = key.ToLowerInvariant();
            if (k.Length > 0 && (lower.EndsWith("/" + k, StringComparison.Ordinal) || lower.Contains(k, StringComparison.Ordinal)))
            {
                return label;
            }
        }
        return null;
    }

    private static RuleMatch Match(string ruleId, Decision decision, string reason, string matchedArgument) =>
        new(ruleId, Category, decision, reason, matchedArgument);

    private sealed class ConfidentialSourceToUntrustedSinkRule : IRule
    {
        public string Id => "TG08-confidential-source-to-untrusted-sink";
        public string Category => InformationFlowRules.Category;
        public string Description =>
            "A call reads from a source labeled confidential-or-higher and writes/sends to a destination " +
            "whose declared trust tier is lower than the source's label, or whose trust tier was never " +
            "declared at all (fails closed to require-approval, not allow).";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var ifc = ctx.Scope.Ifc;
            if (ifc is null) return null;

            var source = FirstString(ctx.Args, SourceKeys);
            if (source is null) return null;
            var sourceLabel = LookupLabel(source, ifc.Sources);
            if (sourceLabel is null || sourceLabel == ConfidentialityLabel.Public) return null;

            var sink = FirstString(ctx.Args, SinkKeys);
            if (sink is null) return null;

            var sinkTrust = LookupLabel(sink, ifc.SinkTrust);
            if (sinkTrust is null)
            {
                return Match(Id, Decision.RequireApproval,
                    $"Call reads from \"{source}\" labeled \"{sourceLabel}\" and sends to \"{sink}\", whose " +
                    "trust tier is not declared in the IFC policy. Failing closed pending human review.", sink);
            }
            if (LabelRank(sinkTrust.Value) < LabelRank(sourceLabel.Value))
            {
                return Match(Id, Decision.Deny,
                    $"Call reads from \"{source}\" labeled \"{sourceLabel}\" but destination \"{sink}\" is only " +
                    $"trusted for \"{sinkTrust}\" data.", sink);
            }
            return null;
        }
    }

    public static readonly IReadOnlyList<IRule> Rules = [new ConfidentialSourceToUntrustedSinkRule()];
}
