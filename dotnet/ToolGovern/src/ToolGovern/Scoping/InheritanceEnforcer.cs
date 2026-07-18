using ToolGovern.Shared;

namespace ToolGovern.Scoping;

/// <summary>
/// Default-deny scope inheritance. When a coordinator agent spawns a sub-agent, the sub-agent
/// does NOT inherit the coordinator's full access by default. Its scope is the intersection of
/// what it requests and what the coordinator itself actually has -- anything requested but not
/// covered by the coordinator's own scope is silently dropped, never silently granted.
/// <see cref="ScopeRegistry"/> is the runtime home for this: it records every agent's effective
/// (granted) scope and re-checks it on every call a rule evaluates, not just once at spawn time.
/// </summary>
public static class InheritanceEnforcer
{
    private static NetworkScope IntersectNetwork(NetworkScope coordinator, NetworkScope requested)
    {
        if (coordinator.IsDisabled || requested.IsDisabled) return NetworkScope.False;
        if (coordinator.IsUnrestricted && requested.IsUnrestricted) return NetworkScope.True;

        var coordinatorList = coordinator.IsUnrestricted ? null : coordinator.Allowlist;
        var requestedList = requested.IsUnrestricted ? null : requested.Allowlist;
        if (coordinatorList is null) return NetworkScope.FromAllowlist(requestedList ?? []);
        if (requestedList is null) return NetworkScope.FromAllowlist(coordinatorList);

        // For each (coordinator, requested) pair that are the same host or one is a subdomain of
        // the other, grant the NARROWER of the two -- not unconditionally whichever list's entry
        // matched. See the TypeScript original's comment: filtering only the coordinator list
        // grants a sub-agent that asked for a narrow host the coordinator's much broader entry
        // whenever the broader entry's domain happens to cover the narrow request; filtering only
        // the requested list breaks the opposite case.
        var granted = new List<string>();
        foreach (var coordHost in coordinatorList)
        {
            foreach (var reqHost in requestedList)
            {
                if (coordHost == reqHost)
                {
                    if (!granted.Contains(coordHost)) granted.Add(coordHost);
                }
                else if (PathUtil.HostMatchesAllowed(coordHost, reqHost))
                {
                    if (!granted.Contains(coordHost)) granted.Add(coordHost);
                }
                else if (PathUtil.HostMatchesAllowed(reqHost, coordHost))
                {
                    if (!granted.Contains(reqHost)) granted.Add(reqHost);
                }
            }
        }
        return NetworkScope.FromAllowlist(granted);
    }

    private static IReadOnlyList<string> IntersectFilesystem(IReadOnlyList<string> coordinator, IReadOnlyList<string> requested) =>
        requested.Where(reqPath => coordinator.Any(coordPath => PathUtil.IsPathWithin(reqPath, coordPath))).ToList();

    private static IReadOnlyList<string> IntersectCredentials(IReadOnlyList<string> coordinator, IReadOnlyList<string> requested) =>
        requested.Where(reqCred => coordinator.Any(coordCred => PathUtil.CredentialMatchesGranted(reqCred, coordCred))).ToList();

    /// <summary>
    /// True if scope carries no capability at all -- no network access, no filesystem prefix, and
    /// no credential. An agent whose granted scope is this empty cannot legitimately make any tool
    /// call, regardless of what the call's arguments happen to look like.
    /// </summary>
    public static bool HasZeroCapability(ScopeDeclaration scope)
    {
        var hasNetwork = scope.Network.IsUnrestricted || (scope.Network.IsAllowlist && scope.Network.Allowlist.Count > 0);
        return !hasNetwork && scope.Filesystem.Count == 0 && scope.Credentials.Count == 0;
    }

    /// <summary>
    /// Pure function: given a coordinator's own effective scope and a sub-agent's requested scope,
    /// returns the scope actually granted. Never returns anything the coordinator itself does not
    /// have, and never grants anything the sub-agent did not explicitly request.
    /// </summary>
    public static ScopeDeclaration ComputeInheritedScope(ScopeDeclaration coordinatorScope, ScopeDeclaration requestedScope) => new()
    {
        Network = IntersectNetwork(coordinatorScope.Network, requestedScope.Network),
        Filesystem = IntersectFilesystem(coordinatorScope.Filesystem, requestedScope.Filesystem),
        Credentials = IntersectCredentials(coordinatorScope.Credentials, requestedScope.Credentials),
    };
}

public sealed class SpawnSubAgentParams
{
    public required string CoordinatorId { get; init; }
    public required string SubAgentId { get; init; }
    public required string SessionId { get; init; }
    public required ScopeDeclaration RequestedScope { get; init; }
}

/// <summary>
/// Tracks every agent's effective (granted) scope for a governed run. Root agents register their
/// own declared scope directly; sub-agents are spawned against a coordinator and receive the
/// intersection of what they request and what their coordinator actually has.
/// </summary>
public sealed class ScopeRegistry : IScopeRegistryReader
{
    private readonly Dictionary<string, AgentScopeRecord> _records = new();

    public AgentScopeRecord RegisterRootAgent(string agentId, string sessionId, ScopeDeclaration scope)
    {
        var record = new AgentScopeRecord { AgentId = agentId, SessionId = sessionId, GrantedScope = scope };
        _records[agentId] = record;
        return record;
    }

    /// <summary>
    /// Spawns a sub-agent under coordinatorId. If the coordinator has never been registered, the
    /// sub-agent is granted the empty scope -- default-deny applies even when the caller forgot to
    /// register the coordinator first, rather than falling back to "unrestricted."
    /// </summary>
    public AgentScopeRecord SpawnSubAgent(SpawnSubAgentParams parameters)
    {
        _records.TryGetValue(parameters.CoordinatorId, out var coordinatorRecord);
        var coordinatorScope = coordinatorRecord?.GrantedScope ?? ScopeDeclarationHelpers.EmptyScope;
        var grantedScope = InheritanceEnforcer.ComputeInheritedScope(coordinatorScope, parameters.RequestedScope);
        var record = new AgentScopeRecord
        {
            AgentId = parameters.SubAgentId,
            SessionId = parameters.SessionId,
            CoordinatorId = parameters.CoordinatorId,
            RequestedScope = parameters.RequestedScope,
            GrantedScope = grantedScope,
        };
        _records[parameters.SubAgentId] = record;
        return record;
    }

    public AgentScopeRecord? GetRecord(string agentId) => _records.GetValueOrDefault(agentId);

    public ScopeDeclaration? GetEffectiveScope(string agentId) => _records.GetValueOrDefault(agentId)?.GrantedScope;

    public bool Has(string agentId) => _records.ContainsKey(agentId);

    /// <summary>
    /// True if agentId is registered and its granted scope has zero capability. An unregistered
    /// agent is not "zero capability" here -- that case is covered separately by
    /// TG05-unregistered-sub-agent, so this only reports on agents the registry actually has a
    /// grant on record for.
    /// </summary>
    public bool IsZeroCapability(string agentId)
    {
        var record = _records.GetValueOrDefault(agentId);
        return record is not null && InheritanceEnforcer.HasZeroCapability(record.GrantedScope);
    }
}
