namespace ToolGovern;

/// <summary>
/// A gate decision is always one of three values -- there is no fourth "warn and continue" state,
/// because a warning that does not block execution is not governance, it is a log line.
/// </summary>
public enum Decision
{
    Allow,
    Deny,
    RequireApproval,
}

public static class DecisionExtensions
{
    /// <summary>Serializes a <see cref="Decision"/> the same way the TypeScript/Python ports spell
    /// it on the wire ("allow" / "deny" / "require-approval").</summary>
    public static string ToWireString(this Decision decision) => decision switch
    {
        Decision.Allow => "allow",
        Decision.Deny => "deny",
        Decision.RequireApproval => "require-approval",
        _ => throw new ArgumentOutOfRangeException(nameof(decision)),
    };

    public static Decision ParseWireString(string value) => value switch
    {
        "allow" => Decision.Allow,
        "deny" => Decision.Deny,
        "require-approval" => Decision.RequireApproval,
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unrecognized decision."),
    };
}

/// <summary>
/// Where an <c>AgentId</c> came from when a gate decision was made: <c>Explicit</c> means the
/// caller passed <c>options.AgentId</c> to <c>GovernTool()</c> directly; <c>Fallback</c> means no
/// agent id was supplied and toolgovern used its default (<c>"default-agent"</c>). This is
/// provenance, not proof -- toolgovern does not cryptographically verify that a caller actually is
/// the agent it claims to be (see docs/security-model.md in the original repo, "Agent identity is
/// caller-asserted, not cryptographically verified"). Recording the source at least tells an
/// auditor whether a decision was made against a caller-asserted identity or a fallback default.
/// </summary>
public enum AgentIdSource
{
    Explicit,
    Fallback,
}

public static class AgentIdSourceExtensions
{
    public static string ToWireString(this AgentIdSource source) => source switch
    {
        AgentIdSource.Explicit => "explicit",
        AgentIdSource.Fallback => "fallback",
        _ => throw new ArgumentOutOfRangeException(nameof(source)),
    };
}

/// <summary>
/// A confidentiality label for information-flow-control (IFC) checks (TG08): a fixed, closed,
/// ordered set from least to most sensitive -- Public &lt; Internal &lt; Confidential &lt;
/// Restricted. Closed rather than free-form so "is this destination trusted enough for this
/// source" is a well-defined rank comparison.
/// </summary>
public enum ConfidentialityLabel
{
    Public,
    Internal,
    Confidential,
    Restricted,
}

/// <summary>
/// The caller-declared information-flow-control labeling for one agent's tool wrapping, consumed
/// by TG08. <see cref="Sources"/> maps a resource identifier to the label it carries;
/// <see cref="SinkTrust"/> maps a destination identifier to the highest label that destination is
/// trusted to receive. A destination absent from <see cref="SinkTrust"/> is not "declared
/// untrusted" -- it is undeclared, which TG08 treats as ambiguous and requires human approval.
/// </summary>
public sealed class IfcPolicy
{
    public IReadOnlyDictionary<string, ConfidentialityLabel> Sources { get; init; }
        = new Dictionary<string, ConfidentialityLabel>();

    public IReadOnlyDictionary<string, ConfidentialityLabel> SinkTrust { get; init; }
        = new Dictionary<string, ConfidentialityLabel>();
}

/// <summary>
/// A per-agent declared network scope: disabled (no network access at all), unrestricted
/// (discouraged, but supported for local/dev use), or an explicit allowlist of hostnames. Mirrors
/// the TypeScript union type <c>boolean | readonly string[]</c>.
/// </summary>
public sealed class NetworkScope
{
    private readonly IReadOnlyList<string>? _allowlist;

    private NetworkScope(bool isUnrestricted, bool isDisabled, IReadOnlyList<string>? allowlist)
    {
        IsUnrestricted = isUnrestricted;
        IsDisabled = isDisabled;
        _allowlist = allowlist;
    }

    public bool IsUnrestricted { get; }
    public bool IsDisabled { get; }
    public bool IsAllowlist => _allowlist is not null;

    /// <summary>The declared allowlist, when this scope is neither disabled nor unrestricted.</summary>
    public IReadOnlyList<string> Allowlist => _allowlist ?? Array.Empty<string>();

    public static readonly NetworkScope False = new(isUnrestricted: false, isDisabled: true, allowlist: null);
    public static readonly NetworkScope True = new(isUnrestricted: true, isDisabled: false, allowlist: null);

    public static NetworkScope FromAllowlist(IReadOnlyList<string> hosts) =>
        new(isUnrestricted: false, isDisabled: false, allowlist: hosts);

    public override bool Equals(object? obj)
    {
        if (obj is not NetworkScope other) return false;
        if (IsDisabled != other.IsDisabled || IsUnrestricted != other.IsUnrestricted) return false;
        if (IsAllowlist != other.IsAllowlist) return false;
        if (!IsAllowlist) return true;
        return Allowlist.SequenceEqual(other.Allowlist);
    }

    public override int GetHashCode() => HashCode.Combine(IsDisabled, IsUnrestricted, IsAllowlist);
}

/// <summary>
/// A per-agent declared scope. <see cref="Network"/> is disabled/unrestricted/allowlisted.
/// <see cref="Filesystem"/> is a list of path prefixes the agent may read/write/delete under.
/// <see cref="Credentials"/> is a list of credential identifiers the agent may access.
/// <see cref="Ifc"/>, when supplied, declares the confidentiality/trust labeling TG08 evaluates;
/// omitted entirely (the default) means TG08 never fires for this agent.
/// </summary>
public sealed class ScopeDeclaration
{
    public required NetworkScope Network { get; init; }
    public required IReadOnlyList<string> Filesystem { get; init; }
    public required IReadOnlyList<string> Credentials { get; init; }
    public IfcPolicy? Ifc { get; init; }

    public override bool Equals(object? obj)
    {
        if (obj is not ScopeDeclaration other) return false;
        return Network.Equals(other.Network)
            && Filesystem.SequenceEqual(other.Filesystem)
            && Credentials.SequenceEqual(other.Credentials);
    }

    public override int GetHashCode() => HashCode.Combine(Network, Filesystem.Count, Credentials.Count);
}

/// <summary>Rule-level overrides a policy file can apply on top of the shipped rule pack defaults.</summary>
public sealed class RuleOverrides
{
    /// <summary>Rule IDs to skip entirely -- the rule never fires, no matter the arguments.</summary>
    public IReadOnlyList<string>? Disable { get; init; }

    /// <summary>Rule IDs whose default Deny decision should be downgraded to RequireApproval.</summary>
    public IReadOnlyList<string>? RequireApproval { get; init; }
}

/// <summary>
/// A loaded (or inline) policy. <c>GovernToolOptions</c> (in <c>ToolGovern.Middleware</c>) derives
/// from this, so a policy loaded from disk and an inline options object are the same shape.
/// </summary>
public class Policy
{
    /// <summary>Free-form policy label, e.g. "strict-shell". Not used for rule matching, only for trace/UX.</summary>
    public string? PolicyName { get; init; }

    /// <summary>The policy file's declared name, when loaded from YAML via <c>name:</c>.</summary>
    public string? Name { get; init; }

    public required ScopeDeclaration Scope { get; init; }
    public RuleOverrides? Rules { get; init; }

    /// <summary>Decision to use when no rule fires. Defaults to Allow.</summary>
    public Decision DefaultDecision { get; init; } = Decision.Allow;

    public string? AgentId { get; init; }
    public string? SessionId { get; init; }
    public string? CoordinatorId { get; init; }
}

/// <summary>
/// What the scoping registry recorded for one agent: the scope it requested at spawn time (only
/// meaningful for sub-agents) and the scope actually granted after default-deny inheritance was
/// applied against its coordinator's own scope.
/// </summary>
public sealed class AgentScopeRecord
{
    public required string AgentId { get; init; }
    public required string SessionId { get; init; }
    public string? CoordinatorId { get; init; }
    public ScopeDeclaration? RequestedScope { get; init; }
    public required ScopeDeclaration GrantedScope { get; init; }
}

/// <summary>The minimal read surface TG05 needs from the scoping registry, kept here to avoid a
/// classifier -> scoping dependency cycle; <c>ScopeRegistry</c> implements this.</summary>
public interface IScopeRegistryReader
{
    AgentScopeRecord? GetRecord(string agentId);
}

/// <summary>The normalized input every classifier rule evaluates against.</summary>
public sealed class RuleContext
{
    public required string AgentId { get; init; }
    public required string SessionId { get; init; }
    public string? CoordinatorId { get; init; }
    public required string Tool { get; init; }
    public required IReadOnlyDictionary<string, object?> Args { get; init; }
    public required ScopeDeclaration Scope { get; init; }

    /// <summary>Present only when the caller wired a ScopeRegistry into Classify(); used by TG05.</summary>
    public IScopeRegistryReader? ScopeRegistry { get; init; }
}

/// <summary>A single fired rule's result. Decision is never Allow -- a rule either fires or it doesn't.</summary>
public sealed record RuleMatch(
    string RuleId,
    string Category,
    Decision Decision,
    string Reason,
    string? MatchedArgument = null);

/// <summary>A classifier rule: pure function from call context to an optional match.</summary>
public interface IRule
{
    string Id { get; }
    string Category { get; }
    string Description { get; }
    RuleMatch? Evaluate(RuleContext ctx);
}

/// <summary>
/// An async classifier rule: same shape as <see cref="IRule"/>, but its check requires an I/O
/// operation (a DNS lookup, currently) that cannot complete synchronously. Evaluated only by
/// <c>ClassifierEngine.ClassifyAsync()</c>, never by the synchronous <c>Classify()</c>.
/// </summary>
public interface IAsyncRule
{
    string Id { get; }
    string Category { get; }
    string Description { get; }
    Task<RuleMatch?> EvaluateAsync(RuleContext ctx);
}

/// <summary>The classifier's aggregate verdict for one tool call.</summary>
public sealed record ClassifierResult(Decision Decision, IReadOnlyList<RuleMatch> FiredRules);

/// <summary>What the caller supplies to <c>TraceWriter.Append()</c> for one gate decision.</summary>
public sealed class TraceEntryInput
{
    public required string SessionId { get; init; }
    public required string AgentId { get; init; }
    public required string Tool { get; init; }
    public required IReadOnlyDictionary<string, object?> Args { get; init; }
    public required Decision Decision { get; init; }

    /// <summary>Rule IDs that fired for this call. Empty for a clean allow.</summary>
    public required IReadOnlyList<string> RuleFired { get; init; }

    public required ScopeDeclaration DeclaredScope { get; init; }

    /// <summary>Identity of the human who resolved a RequireApproval gate. Null for calls that
    /// never went through human approval.</summary>
    public string? ApprovedBy { get; init; }

    /// <summary>How AgentId was resolved for this call. Null so direct TraceWriter.Append() callers
    /// that predate this field are unaffected; GovernTool() always supplies it.</summary>
    public AgentIdSource? AgentIdSource { get; init; }
}

/// <summary>
/// One append-only, signed trace record. <see cref="Signature"/> is either <c>sha256:&lt;hex&gt;</c>
/// (an unkeyed content hash of everything except the signature itself -- the default) or
/// <c>hmac-sha256:&lt;hex&gt;</c> (a keyed signature, when TraceWriter is given a secret key).
/// <see cref="PriorTraceId"/> chains this entry to the one before it in the same session.
/// </summary>
public sealed class TraceEntry
{
    public required string TraceId { get; init; }
    public required string Timestamp { get; init; }
    public required string SessionId { get; init; }
    public required string AgentId { get; init; }
    public required string Tool { get; init; }
    public required string ArgumentsHash { get; init; }
    public required Decision Decision { get; init; }
    public required IReadOnlyList<string> RuleFired { get; init; }
    public required ScopeDeclaration DeclaredScope { get; init; }

    /// <summary>How AgentId was resolved for this call. Null for the same backward-compatibility
    /// reason as TraceEntryInput.AgentIdSource.</summary>
    public AgentIdSource? AgentIdSource { get; init; }

    public required string Signature { get; init; }
    public string? PriorTraceId { get; init; }

    /// <summary>Identity of the human who resolved a RequireApproval gate, when supplied.</summary>
    public string? ApprovedBy { get; init; }
}
