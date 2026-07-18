namespace ToolGovern.Trace;

/// <summary>
/// Converts between <see cref="TraceEntry"/>/<see cref="ScopeDeclaration"/> and the plain
/// dictionary shapes <see cref="CanonicalJson"/> and the JSON file format both understand.
/// Keeping this conversion in one place is what lets the same "build a dict, canonicalize it"
/// approach serve both content-hashing (<see cref="TraceWriter"/>) and file I/O
/// (<see cref="TraceWriter"/>/<see cref="TraceReader"/>) identically.
/// </summary>
internal static class TraceEntryCodec
{
    public static object NetworkToObject(NetworkScope network)
    {
        if (network.IsDisabled) return false;
        if (network.IsUnrestricted) return true;
        return network.Allowlist.ToList();
    }

    private static NetworkScope NetworkFromObject(object? value) => value switch
    {
        bool b => b ? NetworkScope.True : NetworkScope.False,
        System.Text.Json.JsonElement { ValueKind: System.Text.Json.JsonValueKind.True } => NetworkScope.True,
        System.Text.Json.JsonElement { ValueKind: System.Text.Json.JsonValueKind.False } => NetworkScope.False,
        System.Text.Json.JsonElement { ValueKind: System.Text.Json.JsonValueKind.Array } arr =>
            NetworkScope.FromAllowlist([.. arr.EnumerateArray().Select(e => e.GetString()!)]),
        IEnumerable<object?> list => NetworkScope.FromAllowlist([.. list.Select(o => (string)o!)]),
        _ => NetworkScope.False,
    };

    public static Dictionary<string, object?> ScopeToDict(ScopeDeclaration scope) => new()
    {
        ["network"] = NetworkToObject(scope.Network),
        ["filesystem"] = scope.Filesystem.ToList(),
        ["credentials"] = scope.Credentials.ToList(),
    };

    public static ScopeDeclaration ScopeFromDict(IReadOnlyDictionary<string, object?> dict) => new()
    {
        Network = NetworkFromObject(dict.GetValueOrDefault("network")),
        Filesystem = ToStringList(dict.GetValueOrDefault("filesystem")),
        Credentials = ToStringList(dict.GetValueOrDefault("credentials")),
    };

    private static IReadOnlyList<string> ToStringList(object? value) => value switch
    {
        System.Text.Json.JsonElement { ValueKind: System.Text.Json.JsonValueKind.Array } arr =>
            [.. arr.EnumerateArray().Select(e => e.GetString()!)],
        IEnumerable<object?> list => [.. list.Select(o => (string)o!)],
        _ => [],
    };

    /// <summary>Builds the canonicalizable content dict for one entry, everything except
    /// <c>signature</c>. Mirrors the TypeScript original's <c>entryContent()</c>: optional fields
    /// (<c>agent_id_source</c>, <c>approved_by</c>) are omitted entirely (not written as null)
    /// when absent, so old and new entries without them serialize identically -- <c>prior_trace_id</c>
    /// is always present, since it is an explicit nullable field, not an optional one.</summary>
    public static Dictionary<string, object?> ContentDict(
        string traceId,
        string timestamp,
        string sessionId,
        string agentId,
        string tool,
        string argumentsHash,
        Decision decision,
        IReadOnlyList<string> ruleFired,
        ScopeDeclaration declaredScope,
        AgentIdSource? agentIdSource,
        string? priorTraceId,
        string? approvedBy)
    {
        var dict = new Dictionary<string, object?>
        {
            ["trace_id"] = traceId,
            ["timestamp"] = timestamp,
            ["session_id"] = sessionId,
            ["agent_id"] = agentId,
            ["tool"] = tool,
            ["arguments_hash"] = argumentsHash,
            ["decision"] = decision.ToWireString(),
            ["rule_fired"] = ruleFired.ToList(),
            ["declared_scope"] = ScopeToDict(declaredScope),
        };
        if (agentIdSource is not null) dict["agent_id_source"] = agentIdSource.Value.ToWireString();
        dict["prior_trace_id"] = priorTraceId;
        if (approvedBy is not null) dict["approved_by"] = approvedBy;
        return dict;
    }

    /// <summary>Builds the full writable dict for one entry, including <c>signature</c>.</summary>
    public static Dictionary<string, object?> FullDict(TraceEntry entry)
    {
        var dict = ContentDict(
            entry.TraceId, entry.Timestamp, entry.SessionId, entry.AgentId, entry.Tool,
            entry.ArgumentsHash, entry.Decision, entry.RuleFired, entry.DeclaredScope,
            entry.AgentIdSource, entry.PriorTraceId, entry.ApprovedBy);
        dict["signature"] = entry.Signature;
        return dict;
    }

    public static TraceEntry FromJsonElement(System.Text.Json.JsonElement root)
    {
        string? GetString(string key) =>
            root.TryGetProperty(key, out var v) && v.ValueKind != System.Text.Json.JsonValueKind.Null ? v.GetString() : null;

        var ruleFired = root.TryGetProperty("rule_fired", out var rf)
            ? rf.EnumerateArray().Select(e => e.GetString()!).ToList()
            : new List<string>();

        var declaredScopeElement = root.GetProperty("declared_scope");
        var declaredScope = ScopeFromDict(JsonElementToDict(declaredScopeElement));

        var agentIdSourceRaw = GetString("agent_id_source");

        return new TraceEntry
        {
            TraceId = GetString("trace_id")!,
            Timestamp = GetString("timestamp")!,
            SessionId = GetString("session_id")!,
            AgentId = GetString("agent_id")!,
            Tool = GetString("tool")!,
            ArgumentsHash = GetString("arguments_hash")!,
            Decision = DecisionExtensions.ParseWireString(GetString("decision")!),
            RuleFired = ruleFired,
            DeclaredScope = declaredScope,
            AgentIdSource = agentIdSourceRaw is null ? null : agentIdSourceRaw == "explicit" ? AgentIdSource.Explicit : AgentIdSource.Fallback,
            Signature = GetString("signature")!,
            PriorTraceId = GetString("prior_trace_id"),
            ApprovedBy = GetString("approved_by"),
        };
    }

    private static Dictionary<string, object?> JsonElementToDict(System.Text.Json.JsonElement element)
    {
        var dict = new Dictionary<string, object?>();
        foreach (var prop in element.EnumerateObject())
        {
            dict[prop.Name] = prop.Value;
        }
        return dict;
    }
}
