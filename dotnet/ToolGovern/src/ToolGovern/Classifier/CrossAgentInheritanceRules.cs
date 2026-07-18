using ToolGovern.Scoping;
using ToolGovern.Shared;

namespace ToolGovern.Classifier;

/// <summary>
/// TG05 -- Cross-Agent Privilege Inheritance. A sub-agent's own declared scope is not what
/// governs it -- what its coordinator actually granted at spawn time is. These rules compare the
/// call's target resource against the ScopeRegistry record for the calling agent.
/// </summary>
public static class CrossAgentInheritanceRules
{
    private const string Category = "TG05";

    private static RuleMatch Match(string ruleId, Decision decision, string reason, string matchedArgument) =>
        new(ruleId, Category, decision, reason, matchedArgument);

    private static bool IsNetworkCovered(string host, NetworkScope network)
    {
        if (network.IsUnrestricted) return true;
        if (network.IsDisabled) return false;
        return network.Allowlist.Any(allowed => PathUtil.HostMatchesAllowed(host, allowed));
    }

    private sealed class UnregisteredSubAgentRule : IRule
    {
        public string Id => "TG05-unregistered-sub-agent";
        public string Category => CrossAgentInheritanceRules.Category;
        public string Description => "A call arrives from a sub-agent with no verifiable spawn-time grant on record.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            if (ctx.CoordinatorId is null) return null;
            if (ctx.ScopeRegistry is null) return null;
            var record = ctx.ScopeRegistry.GetRecord(ctx.AgentId);
            if (record is not null) return null;
            return Match(Id, Decision.Deny,
                $"Agent \"{ctx.AgentId}\" declares coordinator \"{ctx.CoordinatorId}\" but has no registered scope grant.",
                ctx.AgentId);
        }
    }

    private sealed class ZeroCapabilitySubAgentRule : IRule
    {
        public string Id => "TG05-zero-capability-sub-agent";
        public string Category => CrossAgentInheritanceRules.Category;
        public string Description =>
            "A sub-agent whose coordinator granted it zero capability at all attempts a tool call. " +
            "Denied outright, rather than falling through unclassified.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            if (ctx.CoordinatorId is null) return null;
            if (ctx.ScopeRegistry is null) return null;
            var record = ctx.ScopeRegistry.GetRecord(ctx.AgentId);
            if (record?.CoordinatorId is null) return null;
            if (!InheritanceEnforcer.HasZeroCapability(record.GrantedScope)) return null;
            return Match(Id, Decision.Deny,
                $"Agent \"{ctx.AgentId}\" was granted zero tool capability by its coordinator \"{record.CoordinatorId}\"; all tool calls are denied.",
                ctx.AgentId);
        }
    }

    private sealed class NetworkExceedsGrantRule : IRule
    {
        public string Id => "TG05-network-exceeds-grant";
        public string Category => CrossAgentInheritanceRules.Category;
        public string Description => "Target host is within the agent's own request but outside what its coordinator granted.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var record = ctx.ScopeRegistry?.GetRecord(ctx.AgentId);
            if (record?.RequestedScope is null) return null;
            var host = RuleUtil.ExtractCandidateHost(ctx.Args);
            if (host is null) return null;
            var requestedCovers = IsNetworkCovered(host, record.RequestedScope.Network);
            var grantedCovers = IsNetworkCovered(host, record.GrantedScope.Network);
            if (!requestedCovers || grantedCovers) return null;
            return Match(Id, Decision.Deny,
                $"Host \"{host}\" was requested by \"{ctx.AgentId}\" but never granted by its coordinator.", host);
        }
    }

    private sealed class FilesystemExceedsGrantRule : IRule
    {
        public string Id => "TG05-filesystem-exceeds-grant";
        public string Category => CrossAgentInheritanceRules.Category;
        public string Description => "Target path is within the agent's own request but outside what its coordinator granted.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var record = ctx.ScopeRegistry?.GetRecord(ctx.AgentId);
            if (record?.RequestedScope is null) return null;
            var path = RuleUtil.ExtractPath(ctx.Args);
            if (path is null) return null;
            var requestedCovers = record.RequestedScope.Filesystem.Any(prefix => PathUtil.IsPathWithin(path, prefix));
            var grantedCovers = record.GrantedScope.Filesystem.Any(prefix => PathUtil.IsPathWithin(path, prefix));
            if (!requestedCovers || grantedCovers) return null;
            return Match(Id, Decision.Deny,
                $"Path \"{path}\" was requested by \"{ctx.AgentId}\" but never granted by its coordinator.", path);
        }
    }

    private sealed class CredentialExceedsGrantRule : IRule
    {
        public string Id => "TG05-credential-exceeds-grant";
        public string Category => CrossAgentInheritanceRules.Category;
        public string Description => "Target credential is within the agent's own request but outside what its coordinator granted.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var record = ctx.ScopeRegistry?.GetRecord(ctx.AgentId);
            if (record?.RequestedScope is null) return null;
            var identifier = RuleUtil.ExtractCredentialIdentifier(ctx.Args);
            if (identifier is null) return null;
            var requestedCovers = record.RequestedScope.Credentials.Any(c => PathUtil.CredentialMatchesGranted(identifier, c));
            var grantedCovers = record.GrantedScope.Credentials.Any(c => PathUtil.CredentialMatchesGranted(identifier, c));
            if (!requestedCovers || grantedCovers) return null;
            return Match(Id, Decision.Deny,
                $"Credential \"{identifier}\" was requested by \"{ctx.AgentId}\" but never granted by its coordinator.", identifier);
        }
    }

    private sealed class CoordinatorScopeShrunkRule : IRule
    {
        public string Id => "TG05-coordinator-scope-shrunk";
        public string Category => CrossAgentInheritanceRules.Category;
        public string Description => "The coordinator's own current scope no longer covers what it granted this sub-agent at spawn time.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var record = ctx.ScopeRegistry?.GetRecord(ctx.AgentId);
            if (record?.CoordinatorId is null || ctx.ScopeRegistry is null) return null;
            var coordinatorRecord = ctx.ScopeRegistry.GetRecord(record.CoordinatorId);
            if (coordinatorRecord is null) return null;

            var path = RuleUtil.ExtractPath(ctx.Args);
            var host = RuleUtil.ExtractCandidateHost(ctx.Args);
            var identifier = RuleUtil.ExtractCredentialIdentifier(ctx.Args);

            if (path is not null)
            {
                var stillGrantedBySelf = record.GrantedScope.Filesystem.Any(p => PathUtil.IsPathWithin(path, p));
                var coordinatorStillHasIt = coordinatorRecord.GrantedScope.Filesystem.Any(p => PathUtil.IsPathWithin(path, p));
                if (stillGrantedBySelf && !coordinatorStillHasIt)
                {
                    return Match(Id, Decision.Deny,
                        $"Coordinator \"{record.CoordinatorId}\" no longer covers path \"{path}\" it previously granted to \"{ctx.AgentId}\".",
                        path);
                }
            }
            if (host is not null)
            {
                var stillGrantedBySelf = IsNetworkCovered(host, record.GrantedScope.Network);
                var coordinatorStillHasIt = IsNetworkCovered(host, coordinatorRecord.GrantedScope.Network);
                if (stillGrantedBySelf && !coordinatorStillHasIt)
                {
                    return Match(Id, Decision.Deny,
                        $"Coordinator \"{record.CoordinatorId}\" no longer covers host \"{host}\" it previously granted to \"{ctx.AgentId}\".",
                        host);
                }
            }
            if (identifier is not null)
            {
                var stillGrantedBySelf = record.GrantedScope.Credentials.Any(c => PathUtil.CredentialMatchesGranted(identifier, c));
                var coordinatorStillHasIt = coordinatorRecord.GrantedScope.Credentials.Any(c => PathUtil.CredentialMatchesGranted(identifier, c));
                if (stillGrantedBySelf && !coordinatorStillHasIt)
                {
                    return Match(Id, Decision.Deny,
                        $"Coordinator \"{record.CoordinatorId}\" no longer covers credential \"{identifier}\" it previously granted to \"{ctx.AgentId}\".",
                        identifier);
                }
            }
            return null;
        }
    }

    public static readonly IReadOnlyList<IRule> Rules =
    [
        new UnregisteredSubAgentRule(),
        new ZeroCapabilitySubAgentRule(),
        new NetworkExceedsGrantRule(),
        new FilesystemExceedsGrantRule(),
        new CredentialExceedsGrantRule(),
        new CoordinatorScopeShrunkRule(),
    ];
}
