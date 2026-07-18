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

    def test_denies_outright_for_metadata_endpoint(self, ctx_factory):
        ctx = ctx_factory({"host": "169.254.169.254"}, scope=ScopeDeclaration(network=["other.example"]))
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG03-raw-ip-literal" in ids

    def test_denies_the_same_metadata_endpoint_in_decimal_form(self, ctx_factory):
        # 2852039166 is 169.254.169.254 packed into a single 32-bit unsigned integer -- a
        # dotted-decimal-only IP-literal check never recognizes this as an IP at all, letting
        # it slip past the metadata hard-deny entirely.
        ctx = ctx_factory({"host": "2852039166"}, scope=ScopeDeclaration(network=["other.example"]))
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG03-raw-ip-literal" in ids

    def test_recognizes_a_decimal_encoded_public_ip_as_an_ip_literal_too(self, ctx_factory):
        # Sanity check that the decimal form is recognized as an IP literal in the first
        # place, not just for metadata/private targets: TG03-raw-ip-literal's own verdict for
        # a decimal-encoded public address not in scope is require-approval, same as its
        # dotted-decimal equivalent would be. (The overall classify() decision for this
        # input is "deny" because TG03-host-not-in-scope also independently fires -- this
        # checks TG03-raw-ip-literal's own match, not the aggregate.)
        # 3405803781 == 203.0.113.5
        ctx = ctx_factory({"host": "3405803781"}, scope=ScopeDeclaration(network=["example.com"]))
        decision, ids = _fired(ctx)
        assert "TG03-raw-ip-literal" in ids
        match = next(r for r in classify(ctx).fired_rules if r.rule_id == "TG03-raw-ip-literal")
        assert match.decision == "require-approval"

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

    def test_metadata_endpoint_still_denied_under_unrestricted_network_scope(self, ctx_factory):
        # A blanket network=True (unrestricted) grant must NOT bypass the metadata/private
        # hard-deny -- that's the entire point of "never approvable" (see
        # is_private_or_metadata_target's docstring). A cloud-metadata SSRF target must be
        # denied even for an agent with otherwise-unrestricted network access; only an
        # explicit, exact allowlist entry for this specific host is honored (see
        # test_honors_an_explicit_allowlist_entry_for_a_private_ip below).
        ctx = ctx_factory({"host": "169.254.169.254"}, scope=ScopeDeclaration(network=True))
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG03-raw-ip-literal" in ids

    def test_honors_an_explicit_allowlist_entry_for_a_private_ip(self, ctx_factory):
        # Unlike a blanket network=True grant, an explicit allowlist entry naming this exact
        # private/metadata address is a deliberate, specific operator decision and is honored.
        ctx = ctx_factory(
            {"host": "169.254.169.254"}, scope=ScopeDeclaration(network=["169.254.169.254"])
        )
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
