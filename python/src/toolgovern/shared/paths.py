"""Low-level path/host normalization helpers shared by the classifier and the scoping registry.

Ported from ``packages/toolgovern/src/shared/paths.ts``. Kept dependency-free and
side-effect-free so both modules can import from here without a classifier <-> scoping cycle.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse

_SCHEME_PATTERN = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_BRACKETED_HOST_PATTERN = re.compile(r"^\[([^\]]+)\]")


def normalize_path(raw_path: str) -> str:
    """Collapses ``./``, trailing slashes, and duplicate slashes for stable prefix comparison."""
    path = raw_path.strip()
    if path.startswith("./"):
        path = path[2:]
    path = re.sub(r"/+", "/", path)
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path


def is_path_within(candidate: str, prefix: str) -> bool:
    """True if ``candidate`` is equal to, or a path-segment child of, ``prefix``."""
    normalized_candidate = normalize_path(candidate)
    normalized_prefix = normalize_path(prefix)
    if normalized_prefix in ("", "."):
        return True
    return normalized_candidate == normalized_prefix or normalized_candidate.startswith(
        f"{normalized_prefix}/"
    )


def contains_path_traversal(raw_path: str) -> bool:
    """True if the path contains a ``..`` segment that could escape a scoped prefix via traversal."""
    return ".." in raw_path.split("/")


def normalize_host(host_like: str) -> str:
    """Best-effort hostname extraction from a bare host string or a full URL."""
    trimmed = host_like.strip()
    if _SCHEME_PATTERN.match(trimmed):
        try:
            hostname = urlparse(trimmed).hostname
            if hostname:
                return hostname.lower()
        except ValueError:
            pass  # fall through to the raw-string heuristics below

    without_path = trimmed.split("/", 1)[0] if trimmed else trimmed
    # A bracketed IPv6 literal ([::1] or [::1]:8080) -- unwrap the brackets and drop any
    # trailing port, but keep the address itself intact.
    bracketed = _BRACKETED_HOST_PATTERN.match(without_path)
    if bracketed:
        return (bracketed.group(1) or "").lower()
    # A bare host containing more than one colon is an IPv6 literal, not a host:port pair --
    # splitting on the first colon (as below) would truncate the address.
    if without_path.count(":") >= 2:
        return without_path.lower()
    without_port = without_path.split(":", 1)[0] if without_path else without_path
    return without_port.lower()


def _is_ipv4_literal(host: str) -> bool:
    """True if ``host`` is a raw IPv4 literal (not a domain name)."""
    return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host))


def _strip_ipv6_decoration(host: str) -> str:
    """Strips an optional surrounding ``[...]`` bracket pair and a trailing ``%zone`` scope id
    from an IPv6 literal, e.g. ``[fe80::1%eth0]`` -> ``fe80::1``."""
    h = host.strip()
    bracketed = re.match(r"^\[([^\]]+)\]$", h)
    if bracketed:
        h = bracketed.group(1) or ""
    zone_index = h.find("%")
    if zone_index != -1:
        h = h[:zone_index]
    return h


_HEXTET_PATTERN = re.compile(r"^[0-9a-f]{1,4}$", re.IGNORECASE)


def _parse_ipv6_groups(host: str) -> Optional[List[int]]:
    """Parses a bare (undecorated) IPv6 literal into its eight 16-bit groups, expanding a
    single ``::`` run and an embedded IPv4 tail. Returns ``None`` if not syntactically valid."""
    if ":" not in host:
        return None
    has_double_colon = "::" in host
    if host.count("::") > 1:
        return None

    head, tail = host, ""
    if has_double_colon:
        parts = host.split("::")
        if len(parts) != 2:
            return None
        head, tail = parts[0], parts[1]

    def split_hextets(segment: str) -> List[str]:
        return segment.split(":") if segment else []

    head_parts = split_hextets(head)
    tail_parts = split_hextets(tail)

    # An embedded IPv4 tail (::ffff:169.254.169.254) contributes two hextets worth of bits.
    embedded_ipv4: Optional[List[int]] = None
    if tail_parts:
        last_tail_part = tail_parts[-1]
        if last_tail_part and _is_ipv4_literal(last_tail_part):
            octets_str = last_tail_part.split(".")
            if len(octets_str) != 4:
                return None
            try:
                octets = [int(o) for o in octets_str]
            except ValueError:
                return None
            if any(o > 255 for o in octets):
                return None
            o0, o1, o2, o3 = octets
            embedded_ipv4 = [(o0 << 8) | o1, (o2 << 8) | o3]
            tail_parts.pop()

    if any(not _HEXTET_PATTERN.match(p) for p in head_parts):
        return None
    if any(not _HEXTET_PATTERN.match(p) for p in tail_parts):
        return None

    head_groups = [int(p, 16) for p in head_parts]
    tail_groups = [int(p, 16) for p in tail_parts]
    embedded_length = 2 if embedded_ipv4 else 0
    total = len(head_groups) + len(tail_groups) + embedded_length

    if has_double_colon:
        zeros = 8 - total
        if zeros < 0:
            return None
        groups = head_groups + [0] * zeros + tail_groups + (embedded_ipv4 or [])
    else:
        if total != 8:
            return None
        groups = head_groups + tail_groups + (embedded_ipv4 or [])

    return groups if len(groups) == 8 else None


def _is_ipv6_literal(host: str) -> bool:
    """True if ``host`` is a raw IPv6 literal -- bracketed or bare, with or without a
    ``%zone`` id or an embedded IPv4 tail."""
    return _parse_ipv6_groups(_strip_ipv6_decoration(host)) is not None


def is_ip_literal(host: str) -> bool:
    """True if ``host`` is a raw IP literal, IPv4 or IPv6 (not a domain name)."""
    return _is_ipv4_literal(host) or _is_ipv6_literal(host)


def _is_private_ipv4_octets(octets: Tuple[int, int, int, int]) -> bool:
    """True if IPv4 ``octets`` fall in a loopback, RFC1918-private, or link-local range --
    link-local (169.254.0.0/16) includes the 169.254.169.254 cloud-metadata endpoint used by
    AWS, GCP, Azure, and most other cloud providers."""
    a, b = octets[0], octets[1]
    if a == 127:
        return True  # loopback 127.0.0.0/8
    if a == 10:
        return True  # RFC1918 10.0.0.0/8
    if a == 172 and 16 <= b <= 31:
        return True  # RFC1918 172.16.0.0/12
    if a == 192 and b == 168:
        return True  # RFC1918 192.168.0.0/16
    if a == 169 and b == 254:
        return True  # link-local, incl. cloud metadata 169.254.169.254
    return False


def is_private_or_metadata_target(host: str) -> bool:
    """True if ``host`` is a raw IP literal (v4 or v6) that targets loopback, an
    RFC1918/unique-local private range, link-local space, or a cloud-metadata endpoint
    (169.254.169.254 and its IPv6 equivalents: ::1, fe80::/10, fc00::/7, and IPv4-mapped
    ::ffff:a.b.c.d addresses that resolve into one of the above IPv4 ranges) -- the set of
    destinations a rubber-stamped human approval should never be able to wave through."""
    if _is_ipv4_literal(host):
        octets_str = host.split(".")
        if len(octets_str) != 4:
            return False
        try:
            octets = [int(o) for o in octets_str]
        except ValueError:
            return False
        if any(o > 255 for o in octets):
            return False
        return _is_private_ipv4_octets((octets[0], octets[1], octets[2], octets[3]))

    groups = _parse_ipv6_groups(_strip_ipv6_decoration(host))
    if not groups:
        return False
    g0, g1, g2, g3, g4, g5, g6, g7 = groups

    # ::1 loopback
    if g0 == 0 and g1 == 0 and g2 == 0 and g3 == 0 and g4 == 0 and g5 == 0 and g6 == 0 and g7 == 1:
        return True
    # fe80::/10 link-local
    if (g0 & 0xFFC0) == 0xFE80:
        return True
    # fc00::/7 unique-local
    if (g0 & 0xFE00) == 0xFC00:
        return True
    # IPv4-mapped (::ffff:a.b.c.d) -- check the embedded IPv4 address
    if g0 == 0 and g1 == 0 and g2 == 0 and g3 == 0 and g4 == 0 and g5 == 0xFFFF:
        octets = (g6 >> 8, g6 & 0xFF, g7 >> 8, g7 & 0xFF)
        return _is_private_ipv4_octets(octets)
    return False


def host_matches_allowed(host: str, allowed: str) -> bool:
    """True if ``host`` matches ``allowed`` exactly or is a subdomain of it."""
    h = host.lower()
    a = allowed.lower()
    return h == a or h.endswith(f".{a}")


def credential_matches_granted(identifier: str, granted: str) -> bool:
    """True if ``identifier`` matches ``granted`` exactly, as a path suffix, or as a
    substring -- used for credential-identifier comparisons where declared scopes are often
    coarse-grained (e.g. granting "aws" should cover ".aws/credentials")."""
    i = identifier.lower()
    g = granted.lower()
    return i == g or i.endswith(f"/{g}") or g in i
