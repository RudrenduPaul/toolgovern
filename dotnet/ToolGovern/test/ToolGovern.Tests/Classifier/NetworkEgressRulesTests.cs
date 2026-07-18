using System.Net;
using ToolGovern;
using ToolGovern.Classifier;
using Xunit;

namespace ToolGovern.Tests.Classifier;

public class NetworkEgressRulesTests
{
    private static RuleContext Ctx(Dictionary<string, object?> args, NetworkScope network) => new()
    {
        AgentId = "agent-1",
        SessionId = "session-1",
        Tool = "http.get",
        Args = args,
        Scope = new ScopeDeclaration { Network = network, Filesystem = [], Credentials = [] },
    };

    private static bool Fires(string ruleId, Dictionary<string, object?> args, NetworkScope network)
    {
        var rule = NetworkEgressRules.Rules.First(r => r.Id == ruleId);
        return rule.Evaluate(Ctx(args, network)) is not null;
    }

    private static Decision? DecisionOf(string ruleId, Dictionary<string, object?> args, NetworkScope network)
    {
        var rule = NetworkEgressRules.Rules.First(r => r.Id == ruleId);
        return rule.Evaluate(Ctx(args, network))?.Decision;
    }

    [Fact]
    public void network_disabled_flags_any_host_when_network_scope_false() =>
        Assert.True(Fires("TG03-network-disabled", new() { ["url"] = "https://example.com" }, NetworkScope.False));

    [Fact]
    public void network_disabled_does_not_flag_when_network_scope_allows_hosts() =>
        Assert.False(Fires("TG03-network-disabled", new() { ["url"] = "https://example.com" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void network_disabled_does_not_flag_a_call_with_no_host_at_all() =>
        Assert.False(Fires("TG03-network-disabled", new() { ["command"] = "ls" }, NetworkScope.False));

    [Fact]
    public void host_not_in_scope_flags_a_host_not_in_the_allowlist() =>
        Assert.True(Fires("TG03-host-not-in-scope", new() { ["url"] = "https://attacker.io/x" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void host_not_in_scope_does_not_flag_an_allowlisted_host() =>
        Assert.False(Fires("TG03-host-not-in-scope", new() { ["url"] = "https://api.example.com/x" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void host_not_in_scope_does_not_flag_when_network_unrestricted() =>
        Assert.False(Fires("TG03-host-not-in-scope", new() { ["url"] = "https://anywhere.io" }, NetworkScope.True));

    [Fact]
    public void host_not_in_scope_does_not_evaluate_when_network_false() =>
        Assert.False(Fires("TG03-host-not-in-scope", new() { ["url"] = "https://anywhere.io" }, NetworkScope.False));

    [Fact]
    public void raw_ip_literal_flags_a_raw_ip_literal_target() =>
        Assert.True(Fires("TG03-raw-ip-literal", new() { ["host"] = "203.0.113.5" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void raw_ip_literal_does_not_flag_a_domain_name() =>
        Assert.False(Fires("TG03-raw-ip-literal", new() { ["host"] = "example.com" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void raw_ip_literal_does_not_flag_an_allowlisted_ip_literal() =>
        Assert.False(Fires("TG03-raw-ip-literal", new() { ["host"] = "203.0.113.5" }, NetworkScope.FromAllowlist(["203.0.113.5"])));

    [Fact]
    public void raw_ip_literal_requires_approval_for_public_ip_literal() =>
        Assert.Equal(Decision.RequireApproval, DecisionOf("TG03-raw-ip-literal", new() { ["host"] = "203.0.113.5" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void raw_ip_literal_flags_bracketed_ipv6_loopback() =>
        Assert.True(Fires("TG03-raw-ip-literal", new() { ["host"] = "[::1]" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void raw_ip_literal_flags_bare_ipv6_loopback() =>
        Assert.True(Fires("TG03-raw-ip-literal", new() { ["host"] = "::1" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void raw_ip_literal_flags_ipv6_link_local() =>
        Assert.True(Fires("TG03-raw-ip-literal", new() { ["host"] = "fe80::1" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void raw_ip_literal_flags_ipv6_unique_local() =>
        Assert.True(Fires("TG03-raw-ip-literal", new() { ["host"] = "fc00::1" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void raw_ip_literal_does_not_flag_domain_containing_colons_unrelated() =>
        Assert.False(Fires("TG03-raw-ip-literal", new() { ["host"] = "example.com" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void raw_ip_literal_denies_cloud_metadata_ipv4() =>
        Assert.Equal(Decision.Deny, DecisionOf("TG03-raw-ip-literal", new() { ["host"] = "169.254.169.254" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void raw_ip_literal_denies_metadata_in_bare_decimal_form() =>
        Assert.Equal(Decision.Deny, DecisionOf("TG03-raw-ip-literal", new() { ["host"] = "2852039166" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void raw_ip_literal_recognizes_decimal_encoded_public_ip() =>
        Assert.Equal(Decision.RequireApproval, DecisionOf("TG03-raw-ip-literal", new() { ["host"] = "3405803781" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void raw_ip_literal_denies_ipv4_loopback() =>
        Assert.Equal(Decision.Deny, DecisionOf("TG03-raw-ip-literal", new() { ["host"] = "127.0.0.1" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void raw_ip_literal_denies_rfc1918_private_ipv4() =>
        Assert.Equal(Decision.Deny, DecisionOf("TG03-raw-ip-literal", new() { ["host"] = "10.0.0.5" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void raw_ip_literal_denies_ipv6_loopback() =>
        Assert.Equal(Decision.Deny, DecisionOf("TG03-raw-ip-literal", new() { ["host"] = "::1" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void raw_ip_literal_denies_ipv6_link_local() =>
        Assert.Equal(Decision.Deny, DecisionOf("TG03-raw-ip-literal", new() { ["host"] = "fe80::1" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void raw_ip_literal_denies_ipv4_mapped_ipv6_metadata() =>
        Assert.Equal(Decision.Deny, DecisionOf("TG03-raw-ip-literal", new() { ["host"] = "::ffff:169.254.169.254" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void raw_ip_literal_honors_explicit_allowlist_for_private_ip() =>
        Assert.False(Fires("TG03-raw-ip-literal", new() { ["host"] = "169.254.169.254" }, NetworkScope.FromAllowlist(["169.254.169.254"])));

    [Fact]
    public void non_standard_port_flags_non_standard_port_on_unlisted_host() =>
        Assert.True(Fires("TG03-non-standard-port", new() { ["host"] = "attacker.io:4444" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void non_standard_port_does_not_flag_port_443() =>
        Assert.False(Fires("TG03-non-standard-port", new() { ["host"] = "example.com:443" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void non_standard_port_does_not_flag_host_with_no_port() =>
        Assert.False(Fires("TG03-non-standard-port", new() { ["host"] = "example.com" }, NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void dns_exfil_flags_a_very_long_subdomain_label() =>
        Assert.True(Fires("TG03-dns-exfil-pattern", new() { ["host"] = new string('a', 50) + ".attacker.io" }, NetworkScope.False));

    [Fact]
    public void dns_exfil_does_not_flag_a_normal_short_subdomain() =>
        Assert.False(Fires("TG03-dns-exfil-pattern", new() { ["host"] = "api.example.com" }, NetworkScope.False));

    [Fact]
    public void known_paste_relay_flags_pastebin_mirror() =>
        Assert.True(Fires("TG03-known-paste-relay", new() { ["url"] = "https://pastebin-mirror.io/raw/8x2k" }, NetworkScope.False));

    [Fact]
    public void known_paste_relay_flags_webhook_site() =>
        Assert.True(Fires("TG03-known-paste-relay", new() { ["url"] = "https://webhook.site/abc" }, NetworkScope.False));

    [Fact]
    public void known_paste_relay_does_not_flag_unrelated_domain() =>
        Assert.False(Fires("TG03-known-paste-relay", new() { ["url"] = "https://example.com/data" }, NetworkScope.False));

    [Fact]
    public void known_paste_relay_does_not_flag_when_explicitly_allowlisted() =>
        Assert.False(Fires("TG03-known-paste-relay", new() { ["url"] = "https://transfer.sh/abc" }, NetworkScope.FromAllowlist(["transfer.sh"])));

    [Fact]
    public void nested_host_finds_host_one_level_deep() =>
        Assert.True(Fires("TG03-host-not-in-scope",
            new() { ["params"] = new Dictionary<string, object?> { ["url"] = "https://attacker.io/x" } },
            NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void nested_host_finds_host_several_levels_deep() =>
        Assert.True(Fires("TG03-host-not-in-scope",
            new()
            {
                ["params"] = new Dictionary<string, object?>
                {
                    ["target"] = new Dictionary<string, object?>
                    {
                        ["request"] = new Dictionary<string, object?> { ["host"] = "attacker.io" },
                    },
                },
            },
            NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void nested_host_finds_host_inside_array()
    {
        var calls = new List<object?>
        {
            new Dictionary<string, object?> { ["name"] = "noop" },
            new Dictionary<string, object?> { ["args"] = new Dictionary<string, object?> { ["endpoint"] = "attacker.io" } },
        };
        Assert.True(Fires("TG03-host-not-in-scope", new() { ["calls"] = calls }, NetworkScope.FromAllowlist(["example.com"])));
    }

    [Fact]
    public void nested_host_does_not_flag_when_only_nested_host_allowlisted() =>
        Assert.False(Fires("TG03-host-not-in-scope",
            new() { ["params"] = new Dictionary<string, object?> { ["url"] = "https://api.example.com/x" } },
            NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void nested_host_prefers_top_level_explicit_host_over_nested() =>
        Assert.False(Fires("TG03-host-not-in-scope",
            new()
            {
                ["url"] = "https://api.example.com/x",
                ["params"] = new Dictionary<string, object?> { ["url"] = "https://attacker.io/x" },
            },
            NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void nested_host_flags_raw_ip_literal_nested_inside_mcp_payload() =>
        Assert.Equal(Decision.Deny, DecisionOf("TG03-raw-ip-literal",
            new()
            {
                ["toolCall"] = new Dictionary<string, object?>
                {
                    ["params"] = new Dictionary<string, object?>
                    {
                        ["target"] = new Dictionary<string, object?> { ["host"] = "169.254.169.254" },
                    },
                },
            },
            NetworkScope.FromAllowlist(["example.com"])));

    [Fact]
    public void every_rule_has_a_unique_id_and_belongs_to_TG03()
    {
        var ids = NetworkEgressRules.Rules.Select(r => r.Id).ToHashSet();
        Assert.Equal(NetworkEgressRules.Rules.Count, ids.Count);
        foreach (var rule in NetworkEgressRules.Rules)
        {
            Assert.Equal("TG03", rule.Category);
        }
    }
}

/// <summary>
/// TG03-dns-resolves-private (async DNS-resolution check) -- exercised against an injected
/// resolver rather than the real OS resolver, mirroring the TS suite's <c>vi.mock('node:dns')</c>.
/// Runs in its own collection, sequentially (see xunit.runner.json), because
/// <see cref="NetworkEgressRules.Resolver"/> is process-wide mutable state.
/// </summary>
public class NetworkEgressDnsResolutionTests : IDisposable
{
    private readonly Func<string, Task<IPAddress[]>> _originalResolver = NetworkEgressRules.Resolver;

    public void Dispose() => NetworkEgressRules.Resolver = _originalResolver;

    private static RuleContext Ctx(string host, NetworkScope network) => new()
    {
        AgentId = "agent-1",
        SessionId = "session-1",
        Tool = "http.get",
        Args = new Dictionary<string, object?> { ["host"] = host },
        Scope = new ScopeDeclaration { Network = network, Filesystem = [], Credentials = [] },
    };

    private static Task<RuleMatch?> EvaluateDns(string host, NetworkScope network)
    {
        var rule = NetworkEgressRules.AsyncRules.First(r => r.Id == "TG03-dns-resolves-private");
        return rule.EvaluateAsync(Ctx(host, network));
    }

    [Fact]
    public async Task denies_a_hostname_that_resolves_to_loopback()
    {
        NetworkEgressRules.Resolver = _ => Task.FromResult(new[] { IPAddress.Parse("127.0.0.1") });
        var result = await EvaluateDns("internal-alias.attacker.io", NetworkScope.FromAllowlist(["other.example"]));
        Assert.Equal(Decision.Deny, result?.Decision);
        Assert.Equal("TG03-dns-resolves-private", result?.RuleId);
        Assert.Equal("internal-alias.attacker.io", result?.MatchedArgument);
    }

    [Fact]
    public async Task denies_a_hostname_that_resolves_to_cloud_metadata()
    {
        NetworkEgressRules.Resolver = _ => Task.FromResult(new[] { IPAddress.Parse("169.254.169.254") });
        var result = await EvaluateDns("metadata-lookalike.attacker.io", NetworkScope.FromAllowlist(["other.example"]));
        Assert.NotNull(result);
        Assert.Equal(Decision.Deny, result!.Decision);
        Assert.Contains("169.254.169.254", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task denies_when_one_of_several_resolved_addresses_is_private()
    {
        NetworkEgressRules.Resolver = _ => Task.FromResult(new[] { IPAddress.Parse("203.0.113.5"), IPAddress.Parse("10.0.0.5") });
        var result = await EvaluateDns("multi-homed.attacker.io", NetworkScope.FromAllowlist(["other.example"]));
        Assert.Equal(Decision.Deny, result?.Decision);
    }

    [Fact]
    public async Task allows_a_hostname_that_resolves_only_to_public_addresses()
    {
        NetworkEgressRules.Resolver = _ => Task.FromResult(new[] { IPAddress.Parse("203.0.113.5") });
        var result = await EvaluateDns("public.example", NetworkScope.FromAllowlist(["other.example"]));
        Assert.Null(result);
    }

    [Fact]
    public async Task fails_closed_when_dns_resolution_rejects()
    {
        NetworkEgressRules.Resolver = _ => Task.FromException<IPAddress[]>(new InvalidOperationException("ENOTFOUND"));
        var result = await EvaluateDns("nonexistent.invalid", NetworkScope.FromAllowlist(["other.example"]));
        Assert.NotNull(result);
        Assert.Equal(Decision.RequireApproval, result!.Decision);
        Assert.Contains("failed", result.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task fails_closed_when_dns_resolution_returns_empty_address_list()
    {
        NetworkEgressRules.Resolver = _ => Task.FromResult(Array.Empty<IPAddress>());
        var result = await EvaluateDns("empty-answer.example", NetworkScope.FromAllowlist(["other.example"]));
        Assert.Equal(Decision.RequireApproval, result?.Decision);
    }

    [Fact]
    public async Task does_not_evaluate_or_call_dns_for_a_raw_ip_literal_argument()
    {
        var called = false;
        NetworkEgressRules.Resolver = _ => { called = true; return Task.FromResult(Array.Empty<IPAddress>()); };
        var result = await EvaluateDns("127.0.0.1", NetworkScope.FromAllowlist(["other.example"]));
        Assert.Null(result);
        Assert.False(called);
    }

    [Fact]
    public async Task honors_explicit_allowlist_entry_even_if_it_resolves_private()
    {
        NetworkEgressRules.Resolver = _ => Task.FromResult(new[] { IPAddress.Parse("127.0.0.1") });
        var result = await EvaluateDns("internal.example", NetworkScope.FromAllowlist(["internal.example"]));
        Assert.Null(result);
    }

    [Fact]
    public async Task does_not_fire_when_network_unrestricted_and_resolved_address_public()
    {
        NetworkEgressRules.Resolver = _ => Task.FromResult(new[] { IPAddress.Parse("203.0.113.5") });
        var result = await EvaluateDns("public.example", NetworkScope.True);
        Assert.Null(result);
    }

    [Fact]
    public async Task still_denies_under_unrestricted_network_when_resolved_address_private()
    {
        NetworkEgressRules.Resolver = _ => Task.FromResult(new[] { IPAddress.Parse("169.254.169.254") });
        var result = await EvaluateDns("metadata-lookalike.attacker.io", NetworkScope.True);
        Assert.Equal(Decision.Deny, result?.Decision);
    }
}
