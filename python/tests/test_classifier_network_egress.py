"""TG03 network-egress classifier tests. Ported in spirit from
packages/toolgovern/test/classifier/network-egress.test.ts -- covers all 7 TG03 rules.
"""

import socket
from unittest.mock import patch

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


class TestDnsResolvesPrivate:
    """TG03-dns-resolves-private: a hostname that RESOLVES (via socket.getaddrinfo) to a
    loopback/private/link-local/cloud-metadata address must be caught, not just a raw IP literal
    argument. Uses unittest.mock.patch to control what the resolver returns deterministically --
    there is no real hostname anyone can rely on always resolving to 169.254.169.254."""

    def _addrinfo(self, *addresses):
        # Minimal shape of what socket.getaddrinfo returns: a list of
        # (family, type, proto, canonname, sockaddr) tuples where sockaddr[0] is the address.
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0)) for address in addresses]

    def test_denies_a_hostname_that_resolves_to_loopback(self, ctx_factory):
        ctx = ctx_factory(
            {"host": "internal-alias.attacker.io"}, scope=ScopeDeclaration(network=["other.example"])
        )
        with patch("socket.getaddrinfo", return_value=self._addrinfo("127.0.0.1")):
            decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG03-dns-resolves-private" in ids

    def test_denies_a_hostname_that_resolves_to_the_cloud_metadata_address(self, ctx_factory):
        ctx = ctx_factory(
            {"host": "metadata-lookalike.attacker.io"},
            scope=ScopeDeclaration(network=["other.example"]),
        )
        with patch("socket.getaddrinfo", return_value=self._addrinfo("169.254.169.254")):
            decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG03-dns-resolves-private" in ids

    def test_denies_when_only_one_of_several_resolved_addresses_is_private(self, ctx_factory):
        ctx = ctx_factory(
            {"host": "multi-homed.attacker.io"}, scope=ScopeDeclaration(network=["other.example"])
        )
        with patch("socket.getaddrinfo", return_value=self._addrinfo("203.0.113.5", "10.0.0.5")):
            decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG03-dns-resolves-private" in ids

    def test_allows_a_hostname_that_resolves_only_to_public_addresses(self, ctx_factory):
        ctx = ctx_factory(
            {"host": "public.example"}, scope=ScopeDeclaration(network=["other.example"])
        )
        with patch("socket.getaddrinfo", return_value=self._addrinfo("203.0.113.5")):
            decision, ids = _fired(ctx)
        assert "TG03-dns-resolves-private" not in ids

    def test_fails_closed_require_approval_when_dns_resolution_raises(self, ctx_factory):
        ctx = ctx_factory(
            {"host": "nonexistent.invalid"}, scope=ScopeDeclaration(network=["other.example"])
        )
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
            match = next(
                r for r in network_egress_rules if r.id == "TG03-dns-resolves-private"
            ).evaluate(ctx)
        assert match is not None
        assert match.decision == "require-approval"
        assert "failed" in match.reason.lower()

    def test_fails_closed_when_dns_resolution_times_out(self, ctx_factory):
        ctx = ctx_factory(
            {"host": "slow-resolver.example"}, scope=ScopeDeclaration(network=["other.example"])
        )

        def _hang(*_args, **_kwargs):
            import time

            time.sleep(10)
            return self._addrinfo("203.0.113.5")

        rule = next(r for r in network_egress_rules if r.id == "TG03-dns-resolves-private")
        with patch(
            "toolgovern.classifier.network_egress._DNS_LOOKUP_TIMEOUT_SECONDS", 0.05
        ), patch("socket.getaddrinfo", side_effect=_hang):
            match = rule.evaluate(ctx)
        assert match is not None
        assert match.decision == "require-approval"
        assert "timed out" in match.reason.lower() or "failed" in match.reason.lower()

    def test_fails_closed_when_dns_resolution_returns_no_addresses(self, ctx_factory):
        ctx = ctx_factory(
            {"host": "empty-answer.example"}, scope=ScopeDeclaration(network=["other.example"])
        )
        with patch("socket.getaddrinfo", return_value=[]):
            result = classify(ctx)
        match = next(r for r in result.fired_rules if r.rule_id == "TG03-dns-resolves-private")
        assert match.decision == "require-approval"

    def test_does_not_call_dns_for_a_raw_ip_literal_argument(self, ctx_factory):
        # TG03-raw-ip-literal already owns raw IP literals; the DNS rule should not even attempt
        # a lookup for one.
        ctx = ctx_factory({"host": "127.0.0.1"}, scope=ScopeDeclaration(network=["other.example"]))
        with patch("socket.getaddrinfo") as mocked_getaddrinfo:
            rule = next(r for r in network_egress_rules if r.id == "TG03-dns-resolves-private")
            result = rule.evaluate(ctx)
        assert result is None
        mocked_getaddrinfo.assert_not_called()

    def test_honors_an_explicit_allowlist_entry_even_if_it_resolves_private(self, ctx_factory):
        ctx = ctx_factory(
            {"host": "internal.example"}, scope=ScopeDeclaration(network=["internal.example"])
        )
        with patch("socket.getaddrinfo", return_value=self._addrinfo("127.0.0.1")):
            rule = next(r for r in network_egress_rules if r.id == "TG03-dns-resolves-private")
            result = rule.evaluate(ctx)
        assert result is None

    def test_still_denies_under_unrestricted_true_network_scope_when_resolved_private(
        self, ctx_factory
    ):
        ctx = ctx_factory(
            {"host": "metadata-lookalike.attacker.io"}, scope=ScopeDeclaration(network=True)
        )
        with patch("socket.getaddrinfo", return_value=self._addrinfo("169.254.169.254")):
            decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG03-dns-resolves-private" in ids


class TestDnsResolvesPrivateRealResolver:
    """The same rule exercised against the REAL OS resolver (socket.getaddrinfo, not mocked) --
    localhost is the one hostname genuinely safe to assert on across any CI/sandbox environment
    with no network access at all, since every POSIX /etc/hosts maps it to 127.0.0.1 and
    getaddrinfo honors /etc/hosts before any network round-trip."""

    def test_denies_localhost_via_a_real_hosts_file_backed_lookup(self, ctx_factory):
        ctx = ctx_factory({"host": "localhost"}, scope=ScopeDeclaration(network=["other.example"]))
        decision, ids = _fired(ctx)
        assert decision == "deny"
        assert "TG03-dns-resolves-private" in ids

    def test_fails_closed_for_a_hostname_the_real_resolver_cannot_resolve(self, ctx_factory):
        # RFC 2606 reserves the .invalid TLD specifically so it is guaranteed to never resolve.
        ctx = ctx_factory(
            {"host": "this-host-genuinely-does-not-exist.invalid"},
            scope=ScopeDeclaration(network=["other.example"]),
        )
        match = next(
            r for r in network_egress_rules if r.id == "TG03-dns-resolves-private"
        ).evaluate(ctx)
        assert match is not None
        assert match.decision == "require-approval"


def test_rule_registry_has_seven_tg03_rules():
    assert len(network_egress_rules) == 7
    assert len({r.id for r in network_egress_rules}) == 7
