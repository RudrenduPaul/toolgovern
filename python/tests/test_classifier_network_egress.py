"""TG03 network-egress classifier tests. Ported in spirit from
packages/toolgovern/test/classifier/network-egress.test.ts -- covers all 6 TG03 rules.
"""

from toolgovern import ScopeDeclaration
from toolgovern.classifier.network_egress import network_egress_rules
from toolgovern.classifier.index import classify


def _fired(ctx):
    result = classify(ctx)
    return result.decision, [r.rule_id for r in result.fired_rules]


class TestNetworkDisabled:
    def test_fires_when_network_false(self, ctx_factory):
        ctx = ctx_factory({"host": "example.com"}, scope=ScopeDeclaration(network=False))
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG03-network-disabled" in ids

    def test_no_fire_when_network_true(self, ctx_factory):
        ctx = ctx_factory({"host": "example.com"}, scope=ScopeDeclaration(network=True))
        decision, ids = _fired(ctx)
        assert "TG03-network-disabled" not in ids


class TestHostNotInScope:
    def test_fires_for_unlisted_host(self, ctx_factory):
        ctx = ctx_factory({"host": "evil.example"}, scope=ScopeDeclaration(network=["good.example"]))
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG03-host-not-in-scope" in ids

    def test_subdomain_of_allowed_host_matches(self, ctx_factory):
        ctx = ctx_factory({"host": "api.good.example"}, scope=ScopeDeclaration(network=["good.example"]))
        decision, ids = _fired(ctx)
        assert "TG03-host-not-in-scope" not in ids


class TestRawIpLiteral:
    def test_fires_require_approval_for_public_ip(self, ctx_factory):
        ctx = ctx_factory({"host": "203.0.113.5"}, scope=ScopeDeclaration(network=["203.0.113.5"]))
        # host is explicitly allowlisted, so the raw-ip rule itself should not fire here.
        decision, ids = _fired(ctx)
        assert "TG03-raw-ip-literal" not in ids

    def test_fires_require_approval_for_unlisted_public_ip(self, ctx_factory):
        ctx = ctx_factory({"host": "203.0.113.5"}, scope=ScopeDeclaration(network=["other.example"]))
        decision, ids = _fired(ctx)
        assert "TG03-raw-ip-literal" in ids
        match = next(r for r in classify(ctx).fired_rules if r.rule_id == "TG03-raw-ip-literal")
        assert match.decision == "require-approval"

    # Note: network=True (unrestricted) makes TG03-raw-ip-literal a no-op entirely -- the rule
    # returns early on `scope.network is True`, matching the TS original exactly (an
    # unrestricted network scope means no TG03 rule evaluates any host at all, private/metadata
    # IPs included). The "denied outright, never approvable" behavior only matters once you're
    # past that early return: an explicit allowlist scope that does not itself include the
    # private/metadata IP literal.
    def test_denies_outright_for_metadata_endpoint(self, ctx_factory):
        ctx = ctx_factory({"host": "169.254.169.254"}, scope=ScopeDeclaration(network=["other.example"]))
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG03-raw-ip-literal" in ids

    def test_denies_outright_for_loopback(self, ctx_factory):
        ctx = ctx_factory({"host": "127.0.0.1"}, scope=ScopeDeclaration(network=["other.example"]))
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG03-raw-ip-literal" in ids

    def test_denies_outright_for_ipv6_metadata_mapped(self, ctx_factory):
        ctx = ctx_factory(
            {"host": "::ffff:169.254.169.254"}, scope=ScopeDeclaration(network=["other.example"])
        )
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG03-raw-ip-literal" in ids

    def test_denies_outright_for_ipv6_loopback(self, ctx_factory):
        ctx = ctx_factory({"host": "::1"}, scope=ScopeDeclaration(network=["other.example"]))
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG03-raw-ip-literal" in ids

    def test_unrestricted_network_scope_skips_the_rule_entirely(self, ctx_factory):
        # Documents the early-return behavior itself, so it stays a deliberate, tested fact
        # rather than a surprise: network=True short-circuits TG03-raw-ip-literal before the
        # private/metadata check ever runs.
        ctx = ctx_factory({"host": "169.254.169.254"}, scope=ScopeDeclaration(network=True))
        decision, ids = _fired(ctx)
        assert "TG03-raw-ip-literal" not in ids

    def test_domain_name_does_not_fire(self, ctx_factory):
        ctx = ctx_factory({"host": "example.com"}, scope=ScopeDeclaration(network=True))
        decision, ids = _fired(ctx)
        assert "TG03-raw-ip-literal" not in ids


class TestNonStandardPort:
    def test_fires_for_unusual_port(self, ctx_factory):
        ctx = ctx_factory({"host": "example.com:8080"}, scope=ScopeDeclaration(network=["other.example"]))
        decision, ids = _fired(ctx)
        assert "TG03-non-standard-port" in ids

    def test_https_port_does_not_fire(self, ctx_factory):
        ctx = ctx_factory({"host": "example.com:443"}, scope=ScopeDeclaration(network=["example.com"]))
        decision, ids = _fired(ctx)
        assert "TG03-non-standard-port" not in ids


class TestDnsExfilPattern:
    def test_fires_for_long_subdomain_label(self, ctx_factory):
        long_label = "a" * 45
        ctx = ctx_factory({"host": f"{long_label}.evil.example"}, scope=ScopeDeclaration(network=True))
        decision, ids = _fired(ctx)
        assert "TG03-dns-exfil-pattern" in ids

    def test_short_label_does_not_fire(self, ctx_factory):
        ctx = ctx_factory({"host": "api.example.com"}, scope=ScopeDeclaration(network=True))
        decision, ids = _fired(ctx)
        assert "TG03-dns-exfil-pattern" not in ids


class TestKnownPasteRelay:
    def test_fires_for_pastebin(self, ctx_factory):
        ctx = ctx_factory({"host": "pastebin.com"}, scope=ScopeDeclaration(network=True))
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG03-known-paste-relay" in ids

    def test_fires_for_webhook_site_subdomain(self, ctx_factory):
        ctx = ctx_factory({"host": "abc123.webhook.site"}, scope=ScopeDeclaration(network=True))
        decision, ids = _fired(ctx)
        assert "TG03-known-paste-relay" in ids

    def test_unrelated_host_does_not_fire(self, ctx_factory):
        ctx = ctx_factory({"host": "example.com"}, scope=ScopeDeclaration(network=True))
        decision, ids = _fired(ctx)
        assert "TG03-known-paste-relay" not in ids


def test_rule_registry_has_six_tg03_rules():
    assert len(network_egress_rules) == 6
    assert len({r.id for r in network_egress_rules}) == 6
