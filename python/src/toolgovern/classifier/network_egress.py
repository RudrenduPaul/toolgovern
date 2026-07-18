"""TG03 -- Undeclared Network Egress.

Ported from ``packages/toolgovern/src/classifier/network-egress.ts``.

Fires when a call reaches a host not present in the caller's declared network scope
(``scope.network``: ``False`` for no access, ``True`` for unrestricted, or an explicit host
allowlist).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, List, Optional

from ..shared.paths import host_matches_allowed, is_ip_literal, is_private_or_metadata_target
from ..types import RuleContext, RuleMatch
from .util import extract_candidate_host, extract_command, extract_host

_CATEGORY = "TG03"

_KNOWN_RELAY_DOMAINS = [
    "pastebin.com",
    "pastebin-mirror.io",
    "transfer.sh",
    "ngrok.io",
    "ngrok-free.app",
    "requestbin.com",
    "webhook.site",
    "file.io",
]


@dataclass
class _Rule:
    id: str
    category: str
    description: str
    _evaluate: Callable[[RuleContext], Optional[RuleMatch]]

    def evaluate(self, ctx: RuleContext) -> Optional[RuleMatch]:
        return self._evaluate(ctx)


def _match(rule_id: str, decision: str, reason: str, matched_argument: str) -> RuleMatch:
    return RuleMatch(
        rule_id=rule_id,
        category=_CATEGORY,  # type: ignore[arg-type]
        decision=decision,  # type: ignore[arg-type]
        reason=reason,
        matched_argument=matched_argument,
    )


def _is_host_in_scope(host: str, network) -> bool:
    if network is True:
        return True
    if network is False:
        return False
    return any(host_matches_allowed(host, allowed) for allowed in network)


def _network_disabled_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    if ctx.scope.network is not False:
        return None
    host = extract_candidate_host(ctx.args)
    if not host:
        return None
    return _match(
        "TG03-network-disabled",
        "deny",
        f'Network call to "{host}" attempted with network scope disabled.',
        host,
    )


def _host_not_in_scope_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    if ctx.scope.network is False or ctx.scope.network is True:
        return None
    host = extract_candidate_host(ctx.args)
    if not host:
        return None
    if _is_host_in_scope(host, ctx.scope.network):
        return None
    return _match(
        "TG03-host-not-in-scope", "deny", f'Host "{host}" is not in the declared network allowlist.', host
    )


def _raw_ip_literal_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    host = extract_candidate_host(ctx.args)
    if not host or not is_ip_literal(host):
        return None
    # An explicit, exact allowlist entry for this host is honored even if it is private/
    # metadata -- that's a deliberate, specific operator decision (they named this exact
    # address), unlike the blanket scope.network is True grant checked below, which
    # incidentally covers everything including metadata endpoints without the operator ever
    # having considered this specific address.
    if isinstance(ctx.scope.network, (list, tuple)) and host in ctx.scope.network:
        return None
    if is_private_or_metadata_target(host):
        # Loopback, RFC1918/unique-local, link-local, and cloud-metadata targets are denied
        # outright for any scope that did not explicitly name this exact host above -- this
        # check must run before the scope.network is True early-return below, not after it:
        # an agent with unrestricted (but not host-specific) network access must still never
        # be able to reach an internal network or cloud-metadata endpoint via this rule.
        # That's the entire point of "never approvable" -- it cannot be conditional on a
        # blanket network=True grant.
        return _match(
            "TG03-raw-ip-literal",
            "deny",
            f'Connection to loopback/private/cloud-metadata IP literal "{host}" is never approvable.',
            host,
        )
    if ctx.scope.network is True:
        return None
    return _match("TG03-raw-ip-literal", "require-approval", f'Connection to raw IP literal "{host}".', host)


_PORT_PATTERN = re.compile(r":(\d{2,5})\b")


def _non_standard_port_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    raw = extract_host(ctx.args) or extract_command(ctx.args) or ""
    port_match = _PORT_PATTERN.search(raw)
    if not port_match:
        return None
    port = int(port_match.group(1))
    if port in (80, 443):
        return None
    host = extract_candidate_host(ctx.args)
    if not host:
        return None
    if ctx.scope.network is True:
        return None
    if isinstance(ctx.scope.network, (list, tuple)) and host in ctx.scope.network:
        return None
    return _match(
        "TG03-non-standard-port",
        "require-approval",
        f'Connection to "{host}" on non-standard port {port}.',
        f"{host}:{port}",
    )


def _dns_exfil_pattern_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    host = extract_candidate_host(ctx.args)
    if not host:
        return None
    first_label = host.split(".")[0] if host else ""
    if len(first_label) < 40:
        return None
    return _match(
        "TG03-dns-exfil-pattern", "require-approval", f'Unusually long subdomain label on "{host}".', host
    )


def _known_paste_relay_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    host = extract_candidate_host(ctx.args)
    if not host:
        return None
    hit = next(
        (domain for domain in _KNOWN_RELAY_DOMAINS if host == domain or host.endswith(f".{domain}")),
        None,
    )
    if not hit:
        return None
    if isinstance(ctx.scope.network, (list, tuple)) and hit in ctx.scope.network:
        return None
    return _match(
        "TG03-known-paste-relay", "deny", f'Host "{host}" matches known paste/relay service "{hit}".', host
    )


network_egress_rules: List[_Rule] = [
    _Rule("TG03-network-disabled", _CATEGORY, "Any network egress attempted while the agent has no network scope at all.", _network_disabled_evaluate),
    _Rule("TG03-host-not-in-scope", _CATEGORY, "The target host is not present in the declared network allowlist.", _host_not_in_scope_evaluate),
    _Rule("TG03-raw-ip-literal", _CATEGORY, "Connection to a raw IP literal, bypassing a domain-based allowlist.", _raw_ip_literal_evaluate),
    _Rule("TG03-non-standard-port", _CATEGORY, "Connection to a non-standard port on a host outside the allowlist.", _non_standard_port_evaluate),
    _Rule("TG03-dns-exfil-pattern", _CATEGORY, "Suspiciously long, high-entropy subdomain label -- a common DNS-exfil shape.", _dns_exfil_pattern_evaluate),
    _Rule("TG03-known-paste-relay", _CATEGORY, "Target host matches a known paste/relay/tunnel service commonly used for exfil.", _known_paste_relay_evaluate),
]
