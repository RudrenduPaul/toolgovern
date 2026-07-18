using System.Net;
using System.Text.RegularExpressions;
using ToolGovern.Shared;

namespace ToolGovern.Classifier;

/// <summary>
/// TG03 -- Undeclared Network Egress. Fires when a call reaches a host not present in the
/// caller's declared network scope (disabled, unrestricted, or an explicit host allowlist).
/// </summary>
public static partial class NetworkEgressRules
{
    private const string Category = "TG03";

    private static readonly string[] KnownRelayDomains =
    [
        "pastebin.com",
        "pastebin-mirror.io",
        "transfer.sh",
        "ngrok.io",
        "ngrok-free.app",
        "requestbin.com",
        "webhook.site",
        "file.io",
    ];

    private static RuleMatch Match(string ruleId, Decision decision, string reason, string matchedArgument) =>
        new(ruleId, Category, decision, reason, matchedArgument);

    private static bool IsHostInScope(string host, NetworkScope network)
    {
        if (network.IsUnrestricted) return true;
        if (network.IsDisabled) return false;
        return network.Allowlist.Any(allowed => PathUtil.HostMatchesAllowed(host, allowed));
    }

    private sealed class NetworkDisabledRule : IRule
    {
        public string Id => "TG03-network-disabled";
        public string Category => NetworkEgressRules.Category;
        public string Description => "Any network egress attempted while the agent has no network scope at all.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            if (!ctx.Scope.Network.IsDisabled) return null;
            var host = RuleUtil.ExtractCandidateHost(ctx.Args);
            if (host is null) return null;
            return Match(Id, Decision.Deny, $"Network call to \"{host}\" attempted with network scope disabled.", host);
        }
    }

    private sealed class HostNotInScopeRule : IRule
    {
        public string Id => "TG03-host-not-in-scope";
        public string Category => NetworkEgressRules.Category;
        public string Description => "The target host is not present in the declared network allowlist.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            if (ctx.Scope.Network.IsDisabled || ctx.Scope.Network.IsUnrestricted) return null;
            var host = RuleUtil.ExtractCandidateHost(ctx.Args);
            if (host is null) return null;
            if (IsHostInScope(host, ctx.Scope.Network)) return null;
            return Match(Id, Decision.Deny, $"Host \"{host}\" is not in the declared network allowlist.", host);
        }
    }

    private sealed class RawIpLiteralRule : IRule
    {
        public string Id => "TG03-raw-ip-literal";
        public string Category => NetworkEgressRules.Category;
        public string Description => "Connection to a raw IP literal, bypassing a domain-based allowlist.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var host = RuleUtil.ExtractCandidateHost(ctx.Args);
            if (host is null || !RuleUtil.IsIpLiteral(host)) return null;
            if (ctx.Scope.Network.IsAllowlist && ctx.Scope.Network.Allowlist.Contains(host)) return null;
            if (RuleUtil.IsPrivateOrMetadataTarget(host))
            {
                return Match(Id, Decision.Deny,
                    $"Connection to loopback/private/cloud-metadata IP literal \"{host}\" is never approvable.", host);
            }
            if (ctx.Scope.Network.IsUnrestricted) return null;
            return Match(Id, Decision.RequireApproval, $"Connection to raw IP literal \"{host}\".", host);
        }
    }

    private sealed partial class NonStandardPortRule : IRule
    {
        public string Id => "TG03-non-standard-port";
        public string Category => NetworkEgressRules.Category;
        public string Description => "Connection to a non-standard port on a host outside the allowlist.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var raw = RuleUtil.ExtractHost(ctx.Args) ?? RuleUtil.ExtractCommand(ctx.Args) ?? "";
            var portMatch = PortRegex().Match(raw);
            if (!portMatch.Success) return null;
            var port = int.Parse(portMatch.Groups[1].Value);
            if (port == 80 || port == 443) return null;
            var host = RuleUtil.ExtractCandidateHost(ctx.Args);
            if (host is null) return null;
            if (ctx.Scope.Network.IsUnrestricted) return null;
            if (ctx.Scope.Network.IsAllowlist && ctx.Scope.Network.Allowlist.Contains(host)) return null;
            return Match(Id, Decision.RequireApproval, $"Connection to \"{host}\" on non-standard port {port}.", $"{host}:{port}");
        }

        [GeneratedRegex(@":(\d{2,5})\b")]
        private static partial Regex PortRegex();
    }

    private sealed class DnsExfilPatternRule : IRule
    {
        public string Id => "TG03-dns-exfil-pattern";
        public string Category => NetworkEgressRules.Category;
        public string Description => "Suspiciously long, high-entropy subdomain label -- a common DNS-exfil shape.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var host = RuleUtil.ExtractCandidateHost(ctx.Args);
            if (host is null) return null;
            var firstLabel = host.Split('.')[0];
            if (firstLabel.Length < 40) return null;
            return Match(Id, Decision.RequireApproval, $"Unusually long subdomain label on \"{host}\".", host);
        }
    }

    private sealed class KnownPasteRelayRule : IRule
    {
        public string Id => "TG03-known-paste-relay";
        public string Category => NetworkEgressRules.Category;
        public string Description => "Target host matches a known paste/relay/tunnel service commonly used for exfil.";

        public RuleMatch? Evaluate(RuleContext ctx)
        {
            var host = RuleUtil.ExtractCandidateHost(ctx.Args);
            if (host is null) return null;
            var hit = KnownRelayDomains.FirstOrDefault(domain => host == domain || host.EndsWith("." + domain, StringComparison.Ordinal));
            if (hit is null) return null;
            if (ctx.Scope.Network.IsAllowlist && ctx.Scope.Network.Allowlist.Contains(hit)) return null;
            return Match(Id, Decision.Deny, $"Host \"{host}\" matches known paste/relay service \"{hit}\".", host);
        }
    }

    public static readonly IReadOnlyList<IRule> Rules =
    [
        new NetworkDisabledRule(),
        new HostNotInScopeRule(),
        new RawIpLiteralRule(),
        new NonStandardPortRule(),
        new DnsExfilPatternRule(),
        new KnownPasteRelayRule(),
    ];

    /// <summary>How long to wait for a DNS answer before treating the lookup as failed (and
    /// failing closed). Generous enough to not misfire against a normally-slow but legitimate
    /// resolver.</summary>
    private static readonly TimeSpan DnsLookupTimeout = TimeSpan.FromSeconds(3);

    /// <summary>Injectable resolver, used by tests to avoid depending on real DNS/network access.
    /// Defaults to the real OS resolver via <see cref="Dns.GetHostAddressesAsync(string)"/>.</summary>
    public static Func<string, Task<IPAddress[]>> Resolver { get; set; } = host => Dns.GetHostAddressesAsync(host);

    /// <summary>Resolves every address a hostname maps to, racing it against a hard timeout so a
    /// hung/unresponsive resolver cannot stall the call indefinitely. Throws on failure or
    /// timeout -- callers must treat that as "unknown, fail closed."</summary>
    private static async Task<string[]> ResolveHostAddressesAsync(string host)
    {
        var lookupTask = Resolver(host);
        var timeoutTask = Task.Delay(DnsLookupTimeout);
        var completed = await Task.WhenAny(lookupTask, timeoutTask);
        if (completed != lookupTask)
        {
            throw new TimeoutException($"DNS lookup for \"{host}\" timed out after {DnsLookupTimeout.TotalMilliseconds}ms");
        }
        var addresses = await lookupTask;
        return addresses.Select(a => a.ToString()).ToArray();
    }

    private sealed class DnsResolvesToPrivateTargetRule : IAsyncRule
    {
        public string Id => "TG03-dns-resolves-private";
        public string Category => NetworkEgressRules.Category;
        public string Description =>
            "A hostname argument that resolves via DNS to a loopback/RFC1918/link-local/cloud-metadata address, " +
            "even though the argument itself is a domain name, not a raw IP literal.";

        public async Task<RuleMatch?> EvaluateAsync(RuleContext ctx)
        {
            var host = RuleUtil.ExtractCandidateHost(ctx.Args);
            if (host is null || RuleUtil.IsIpLiteral(host)) return null;
            if (ctx.Scope.Network.IsAllowlist && ctx.Scope.Network.Allowlist.Contains(host)) return null;

            string[] addresses;
            try
            {
                addresses = await ResolveHostAddressesAsync(host);
            }
            catch (Exception error)
            {
                return Match(Id, Decision.RequireApproval,
                    $"DNS resolution for host \"{host}\" failed ({error.Message}); failing closed rather than " +
                    "assuming an unresolvable host is safe to reach.", host);
            }

            if (addresses.Length == 0)
            {
                return Match(Id, Decision.RequireApproval,
                    $"DNS resolution for host \"{host}\" returned no addresses; failing closed rather than " +
                    "assuming an unresolvable host is safe to reach.", host);
            }

            var privateAddress = addresses.FirstOrDefault(RuleUtil.IsPrivateOrMetadataTarget);
            if (privateAddress is null) return null;

            return Match(Id, Decision.Deny,
                $"Host \"{host}\" resolves via DNS to loopback/private/cloud-metadata address \"{privateAddress}\" " +
                "-- denied even though the call argument is a hostname, not a raw IP literal. This is a " +
                "resolve-then-check at classification time, not a connection-time guarantee -- it narrows but " +
                "does not eliminate DNS-rebinding TOCTOU.", host);
        }
    }

    /// <summary>Async-only TG03 checks -- currently just DNS resolution of hostname arguments.
    /// Evaluated only by ClassifierEngine.ClassifyAsync(), never by the synchronous Classify().</summary>
    public static readonly IReadOnlyList<IAsyncRule> AsyncRules = [new DnsResolvesToPrivateTargetRule()];
}
