"""Shared argument-extraction helpers for rule implementations.

Ported from ``packages/toolgovern/src/classifier/util.ts``.

Real tool-call argument shapes vary a lot across frameworks -- a shell tool might name its
argument ``command``, ``cmd``, or ``script``. Rather than force every framework to normalize to
one schema before toolgovern can evaluate a call, each rule looks for a small set of common key
names and falls back to scanning the stringified argument bag. This is deliberately permissive
(a false negative here is worse than a rare false positive from the string fallback).
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, List, Mapping, Optional, Sequence

from ..shared.paths import (
    contains_path_traversal as contains_path_traversal,
    is_ip_literal as is_ip_literal,
    is_path_within as is_path_within,
    is_private_or_metadata_target as is_private_or_metadata_target,
    normalize_host as normalize_host,
    normalize_path as normalize_path,
)

_COMMAND_KEYS = ["command", "cmd", "script", "shell", "code"]
_PATH_KEYS = ["path", "target", "dest", "destination", "file", "filepath", "file_path"]
_OPERATION_KEYS = ["operation", "op", "action", "mode"]
_HOST_KEYS = ["host", "hostname", "url", "uri", "endpoint", "address"]
_CREDENTIAL_KEYS = ["credential", "secret", "secretName", "credentialId"]


def _first_string(args: Mapping[str, Any], keys: Sequence[str]) -> Optional[str]:
    for key in keys:
        value = args.get(key)
        if isinstance(value, str) and len(value) > 0:
            return value
    return None


def extract_command(args: Mapping[str, Any]) -> Optional[str]:
    """Extracts a shell-command-like string from common argument key names."""
    return _first_string(args, _COMMAND_KEYS)


def extract_code_text(args: Mapping[str, Any]) -> Optional[str]:
    """Extracts the raw ``code`` string argument a code-execution tool was invoked with, if any."""
    value = args.get("code")
    return value if isinstance(value, str) and len(value) > 0 else None


_CODE_FILE_CALL_PATTERN = re.compile(
    r"\b(?:open|readfile|readfilesync|writefile|writefilesync|unlink|unlinksync|rmsync|"
    r"rmdirsync|chmod|chown|chmodsync|chownsync|os\.remove|os\.unlink|os\.rmdir|os\.chmod|"
    r"os\.chown|fs\.chmod|fs\.chown|shutil\.rmtree|shutil\.copy\w*)\s*\(\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_CODE_BARE_PATH_PATTERN = re.compile(r"[\"'`]((?:\.\./)+[^\"'`]*|/(?:[\w.-]+/)*[\w.-]+)[\"'`]")


def extract_path_from_code(code: str) -> Optional[str]:
    """Scans a code-execution tool's ``code`` string for a path-like literal."""
    call_match = _CODE_FILE_CALL_PATTERN.search(code)
    if call_match and call_match.group(1):
        return call_match.group(1)
    bare_match = _CODE_BARE_PATH_PATTERN.search(code)
    if bare_match and bare_match.group(1):
        return bare_match.group(1)
    return None


_CODE_DELETE_PATTERN = re.compile(
    r"\b(?:os\.remove|os\.unlink|os\.rmdir|shutil\.rmtree|fs\.unlink|fs\.unlinksync|fs\.rm|"
    r"fs\.rmsync|fs\.rmdir|fs\.rmdirsync|unlinksync|rmsync|rmdirsync)\s*\(",
    re.IGNORECASE,
)
_CODE_CHMOD_PATTERN = re.compile(
    r"\b(?:os\.chmod|os\.chown|fs\.chmod|fs\.chmodsync|fs\.chown|fs\.chownsync|chmodsync|"
    r"chownsync)\s*\(",
    re.IGNORECASE,
)
_CODE_WRITE_CALL_PATTERN = re.compile(
    r"\b(?:writefile|writefilesync|fs\.writefile|fs\.writefilesync|os\.write)\s*\(",
    re.IGNORECASE,
)
_CODE_OPEN_WRITE_MODE_PATTERN = re.compile(
    r"\bopen\s*\([^)]*?,\s*[\"'](\w*[wax]\w*)[\"']", re.IGNORECASE
)


def extract_operation_from_code(code: str) -> Optional[str]:
    """Infers a write/delete/chmod operation from a code string's recognized call shapes."""
    if _CODE_DELETE_PATTERN.search(code):
        return "delete"
    if _CODE_CHMOD_PATTERN.search(code):
        return "chmod"
    if _CODE_WRITE_CALL_PATTERN.search(code) or _CODE_OPEN_WRITE_MODE_PATTERN.search(code):
        return "write"
    return None


def extract_path(args: Mapping[str, Any]) -> Optional[str]:
    """Extracts a filesystem-path-like string from common argument key names, falling back to
    scanning a ``code`` string argument when no path/target/dest-style key is present."""
    direct = _first_string(args, _PATH_KEYS)
    if direct:
        return direct
    code = extract_code_text(args)
    return extract_path_from_code(code) if code else None


def extract_operation(args: Mapping[str, Any]) -> Optional[str]:
    """Extracts a declared filesystem operation (read/write/delete/chmod/...) if the tool
    provides one, falling back to inferring one from a ``code`` string argument."""
    direct = _first_string(args, _OPERATION_KEYS)
    if direct:
        return direct.lower()
    code = extract_code_text(args)
    return extract_operation_from_code(code) if code else None


def extract_host(args: Mapping[str, Any]) -> Optional[str]:
    """Extracts a network host/URL-like string from common argument key names."""
    return _first_string(args, _HOST_KEYS)


def extract_credential_name(args: Mapping[str, Any]) -> Optional[str]:
    """Extracts a declared credential identifier from common argument key names."""
    return _first_string(args, _CREDENTIAL_KEYS)


def stringify_args(args: Mapping[str, Any]) -> str:
    """Flattens every string value in the argument bag into one lowercase blob, used as a
    fallback scan target for pattern rules when no known key name matches."""
    parts: List[str] = []
    for value in args.values():
        if isinstance(value, str):
            parts.append(value)
        elif value is not None and not isinstance(value, (dict, list)):
            parts.append(str(value))
    return " ".join(parts).lower()


# Zero-width, bidi-control, and other invisible-format Unicode characters sometimes inserted
# mid-token to break a literal-substring or \b word-boundary match (e.g. "sudo" with a
# zero-width space spliced in). Stripped before pattern matching, never before execution.
# Built from \uXXXX escape sequences (text in this source file, not a pasted glyph) so no
# literal invisible/control character ever lives in this file, and compiled once into a single
# regex -- an earlier version of this function did the equivalent check with a pure-Python
# per-character loop, which was roughly 1000x slower on large inputs (a governance middleware
# that gates every tool call synchronously cannot afford tens of milliseconds per call just to
# strip formatting characters). Ranges: U+00AD soft hyphen, U+200B-200F zero-width
# space/joiners/marks, U+202A-202E bidi embedding/override controls, U+2060-2064 word
# joiner/invisible operators, U+FEFF BOM.
_INVISIBLE_FORMAT_CHARS = re.compile(
    "[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]"
)


def _strip_invisible_format_chars(text: str) -> str:
    return _INVISIBLE_FORMAT_CHARS.sub("", text)

# $IFS / ${IFS} (optionally with a positional-parameter suffix like $9) is a well-known shell
# field-separator substitution attackers use in place of a literal space specifically to dodge
# whitespace-based pattern matching, without changing what the shell actually executes.
_IFS_SEPARATOR = re.compile(r"\$\{?IFS\}?(\$\d+)?", re.IGNORECASE)


def _collapse_empty_quote_pairs(text: str) -> str:
    """An adjacent pair of matching quote characters ('' or "") contributes nothing to what a
    POSIX shell actually runs, but it does break a naive literal-substring match. Collapsed
    here, repeatedly, so stacked pairs are fully removed."""
    current = text
    previous = None
    while current != previous:
        previous = current
        current = re.sub(r"(['\"])\1", "", current)
    return current


def normalize_for_match(text: str) -> str:
    """Normalizes free-form command/argument text before it is matched against a classifier
    pattern. Does not change what actually gets executed -- it only closes the gap between
    "what the shell will run" and "what a literal regex sees" for a handful of well-known
    obfuscation tricks: Unicode confusables/invisible characters, $IFS-as-space substitution,
    and empty-quote-pair token splitting (cu''rl, r""m)."""
    normalized = unicodedata.normalize("NFKC", text)
    normalized = _strip_invisible_format_chars(normalized)
    normalized = _IFS_SEPARATOR.sub(" ", normalized)
    normalized = _collapse_empty_quote_pairs(normalized)
    normalized = re.sub(r"\\([A-Za-z0-9])", r"\1", normalized)
    return normalized


# Maximum object/array nesting depth find_nested_host will descend into. Bounds the search
# against pathological or absurdly nested argument payloads.
_MAX_HOST_SEARCH_DEPTH = 8


def _find_nested_host(value: Any, depth: int = 0) -> Optional[str]:
    """Depth-first search for the first HOST_KEYS-named string value anywhere inside a nested
    argument bag, so a host/URL buried inside a nested payload is still found."""
    if value is None or depth > _MAX_HOST_SEARCH_DEPTH:
        return None

    if isinstance(value, list):
        for item in value:
            found = _find_nested_host(item, depth + 1)
            if found:
                return found
        return None

    if isinstance(value, dict):
        direct = _first_string(value, _HOST_KEYS)
        if direct:
            return direct
        for nested in value.values():
            if isinstance(nested, (dict, list)):
                found = _find_nested_host(nested, depth + 1)
                if found:
                    return found

    return None


_URL_PATTERN = re.compile(r"https?://[^\s\"'|]+", re.IGNORECASE)


def extract_candidate_host(args: Mapping[str, Any]) -> Optional[str]:
    """Pulls a candidate network host out of an explicit host/url argument -- checked at the
    top level first, then recursively through nested objects/arrays -- or otherwise scans a
    shell-command-like string for the first http(s):// URL. Returns a normalized hostname."""
    explicit = extract_host(args) or _find_nested_host(args)
    if explicit:
        return normalize_host(normalize_for_match(explicit))

    command = normalize_for_match(extract_command(args) or stringify_args(args))
    url_match = _URL_PATTERN.search(command)
    if url_match:
        return normalize_host(url_match.group(0))
    return None


def extract_credential_identifier(args: Mapping[str, Any]) -> Optional[str]:
    """Extracts whichever resource identifier a credential-scoped call is targeting -- an
    explicit credential/secret name if the tool provides one, otherwise the filesystem path."""
    return extract_credential_name(args) or extract_path(args)


def is_credential_granted(identifier: str, credentials: Sequence[str]) -> bool:
    """Whether ``identifier`` (a path or a named credential) matches an entry in
    ``credentials`` -- exact match, a trailing path segment match, or a substring match."""
    lower = identifier.lower()
    for granted in credentials:
        g = granted.lower()
        if lower == g or lower.endswith(f"/{g}") or g in lower:
            return True
    return False
