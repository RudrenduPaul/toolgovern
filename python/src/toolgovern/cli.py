"""toolgovern-cli -- validate policy files and audit local gate traces, without needing the
hosted dashboard.

Ported from ``packages/toolgovern-cli/src/cli.ts`` (which uses hand-rolled ``process.argv``
parsing); this port uses the same hand-rolled flag parser translated to Python so the flag
shapes, defaults, and output text stay identical to the npm CLI's behavior.

    toolgovern-cli validate ./toolgovern.policy.yml
    toolgovern-cli audit ./toolgovern-trace.jsonl --since 24h --decision deny
    toolgovern-cli init langgraph

Every command function below returns a ``CliResult`` (exit code + stdout/stderr text) instead of
writing to stdout/stderr directly, so the command logic is testable in isolation -- ``main()`` is
the only place that touches the real process streams.

Note on scope versus the npm CLI: ``init`` scaffolds a *TypeScript* integration file wiring
``governTool()``/``governedLangGraphTools()`` into a Node project -- that scaffold is
JS/TS-specific by nature (it imports ``toolgovern-integration-langgraph``, a JS package) and is
not reproduced here. The Python port's ``validate`` and ``audit`` commands are otherwise
byte-for-byte equivalent in behavior, flags, and output shape (including ``--json``) to the npm
CLI.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Union

import yaml

from .policy.validate_policy import validate_policy
from .trace.trace_reader import TraceQuery, filter_trace, read_trace, verify_chain
from .trace.trace_reader import VerifyChainOptions

_VALID_DECISIONS = {"allow", "deny", "require-approval"}


@dataclass(frozen=True)
class CliResult:
    code: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class ParsedFlags:
    positional: Sequence[str]
    flags: Dict[str, Union[str, bool]]


def _is_json_flag(flags: Dict[str, Any]) -> bool:
    return flags.get("json") is True or flags.get("json") == "true"


def _json_result(code: int, envelope: Dict[str, Any]) -> CliResult:
    return CliResult(code=code, stdout=json.dumps(envelope, indent=2) + "\n", stderr="")


def parse_args(argv: Sequence[str]) -> ParsedFlags:
    positional: List[str] = []
    flags: Dict[str, Union[str, bool]] = {}
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg.startswith("--"):
            key = arg[2:]
            nxt = argv[i + 1] if i + 1 < len(argv) else None
            if nxt is not None and not nxt.startswith("--"):
                flags[key] = nxt
                i += 1
            else:
                flags[key] = True
        else:
            positional.append(arg)
        i += 1
    return ParsedFlags(positional=positional, flags=flags)


USAGE = "\n".join(
    [
        "Usage:",
        "  toolgovern-cli validate <policy-file> [--json]",
        "  toolgovern-cli audit <trace-file> [--since <window>] [--decision <allow|deny|require-approval>] [--agent <id>] [--rule <ruleId>] [--verify-chain] [--key-file <path>] [--json]",
        "",
        "  --json      Emit a single structured JSON object on stdout instead of human-formatted text --",
        "              { ok, command, data } on success, { ok: false, command, error } on failure. Exit",
        "              code still reflects success/failure; nothing is ever split across stdout/stderr",
        "              in --json mode. Meant for another program (an agent, a script) to parse reliably.",
        "",
        "  --key-file  Path to the secret key file used to verify hmac-sha256-signed trace entries.",
        "              Only needed if the trace was written with a TraceWriter secret_key. Entries",
        "              signed with the default unkeyed sha256 scheme verify without it.",
        "",
    ]
)


def validate_command(policy_file: Optional[str], flags: Optional[Dict[str, Any]] = None) -> CliResult:
    flags = flags or {}
    json_mode = _is_json_flag(flags)

    if not policy_file:
        message = "validate requires a <policy-file> argument."
        if json_mode:
            return _json_result(2, {"ok": False, "command": "validate", "error": {"message": message}})
        return CliResult(code=2, stdout="", stderr=f"{message}\n{USAGE}")

    try:
        with open(policy_file, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f.read())
    except Exception as error:
        message = f'Failed to read/parse "{policy_file}": {error}'
        if json_mode:
            return _json_result(1, {"ok": False, "command": "validate", "error": {"message": message}})
        return CliResult(code=1, stdout="", stderr=f"{message}\n")

    result = validate_policy(raw)
    if result.valid:
        if json_mode:
            return _json_result(
                0,
                {
                    "ok": True,
                    "command": "validate",
                    "data": {"file": policy_file, "valid": True, "errors": []},
                },
            )
        return CliResult(code=0, stdout=f"OK  {policy_file} is a valid toolgovern policy.\n", stderr="")

    if json_mode:
        return _json_result(
            1,
            {
                "ok": False,
                "command": "validate",
                "data": {"file": policy_file, "valid": False, "errors": list(result.errors)},
                "error": {
                    "message": f'"{policy_file}" is not a valid toolgovern policy.',
                    "details": list(result.errors),
                },
            },
        )
    stderr = "\n".join([f"INVALID  {policy_file}", *[f"  - {e}" for e in result.errors], ""])
    return CliResult(code=1, stdout="", stderr=stderr)


def audit_command(trace_file: Optional[str], flags: Dict[str, Any]) -> CliResult:
    json_mode = _is_json_flag(flags)

    if not trace_file:
        message = "audit requires a <trace-file> argument."
        if json_mode:
            return _json_result(2, {"ok": False, "command": "audit", "error": {"message": message}})
        return CliResult(code=2, stdout="", stderr=f"{message}\n{USAGE}")

    try:
        entries = read_trace(trace_file)
    except Exception as error:
        message = f'Failed to read trace file "{trace_file}": {error}'
        if json_mode:
            return _json_result(1, {"ok": False, "command": "audit", "error": {"message": message}})
        return CliResult(code=1, stdout="", stderr=f"{message}\n")

    stdout = ""
    chain: Optional[Dict[str, Any]] = None

    if flags.get("verify-chain"):
        secret_key: Optional[bytes] = None
        key_file = flags.get("key-file")
        if isinstance(key_file, str):
            try:
                with open(key_file, "rb") as f:
                    secret_key = f.read()
            except Exception as error:
                message = f'Failed to read --key-file "{key_file}": {error}'
                if json_mode:
                    return _json_result(1, {"ok": False, "command": "audit", "error": {"message": message}})
                return CliResult(code=1, stdout="", stderr=f"{message}\n")
        verification = verify_chain(entries, VerifyChainOptions(secret_key=secret_key))
        if not verification.valid:
            if json_mode:
                return _json_result(
                    1,
                    {
                        "ok": False,
                        "command": "audit",
                        "data": {
                            "file": trace_file,
                            "chain": {"verified": False, "entries": len(entries)},
                            "issues": [
                                {"traceId": i.trace_id, "reason": i.reason} for i in verification.issues
                            ],
                        },
                        "error": {
                            "message": f'Chain verification failed for "{trace_file}".',
                            "details": [f"{i.trace_id}: {i.reason}" for i in verification.issues],
                        },
                    },
                )
            stderr = "\n".join(
                [
                    f"CHAIN INVALID  {trace_file}",
                    *[f"  - {i.trace_id}: {i.reason}" for i in verification.issues],
                    "",
                ]
            )
            return CliResult(code=1, stdout="", stderr=stderr)
        chain = {"verified": True, "entries": len(entries)}
        stdout += f"Chain OK -- {len(entries)} entries verified.\n"

    decision_flag = flags.get("decision") if isinstance(flags.get("decision"), str) else None
    if decision_flag and decision_flag not in _VALID_DECISIONS:
        message = f'--decision must be one of: allow, deny, require-approval (got "{decision_flag}")'
        if json_mode:
            return _json_result(2, {"ok": False, "command": "audit", "error": {"message": message}})
        return CliResult(code=2, stdout="", stderr=f"{message}\n")

    query = TraceQuery(
        since=flags.get("since") if isinstance(flags.get("since"), str) else None,
        decision=decision_flag,  # type: ignore[arg-type]
        agent_id=flags.get("agent") if isinstance(flags.get("agent"), str) else None,
        rule_id=flags.get("rule") if isinstance(flags.get("rule"), str) else None,
    )

    try:
        filtered = filter_trace(entries, query)
    except Exception as error:
        message = str(error)
        if json_mode:
            return _json_result(2, {"ok": False, "command": "audit", "error": {"message": message}})
        return CliResult(code=2, stdout="", stderr=f"{message}\n")

    if json_mode:
        return _json_result(
            0,
            {
                "ok": True,
                "command": "audit",
                "data": {
                    "file": trace_file,
                    "chain": chain,
                    "query": {
                        "since": query.since,
                        "decision": query.decision,
                        "agentId": query.agent_id,
                        "ruleId": query.rule_id,
                    },
                    "matched": len(filtered),
                    "total": len(entries),
                    "entries": [e.to_dict() for e in filtered],
                },
            },
        )

    for entry in filtered:
        rules = ", ".join(entry.rule_fired) if entry.rule_fired else "(no rule fired)"
        stdout += (
            f"{entry.decision.upper():<16} {entry.agent_id} -> {entry.tool}  [{rules}]  {entry.timestamp}\n"
        )
    stdout += f"\n{len(filtered)} of {len(entries)} trace entries matched.\n"

    return CliResult(code=0, stdout=stdout, stderr="")


def run_command(argv: Sequence[str]) -> CliResult:
    command = argv[0] if argv else None
    rest = argv[1:] if argv else []
    parsed = parse_args(rest)
    positional, flags = parsed.positional, parsed.flags

    if not command or command in ("--help", "-h"):
        return CliResult(code=0 if command else 2, stdout=USAGE if command else "", stderr="" if command else USAGE)

    if command == "validate":
        return validate_command(positional[0] if positional else None, flags)

    if command == "audit":
        return audit_command(positional[0] if positional else None, flags)

    message = f'Unknown command "{command}".'
    if _is_json_flag(flags):
        return _json_result(2, {"ok": False, "command": command, "error": {"message": message}})
    return CliResult(code=2, stdout="", stderr=f"{message}\n{USAGE}")


def main() -> None:
    result = run_command(sys.argv[1:])
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    sys.exit(result.code)


if __name__ == "__main__":
    main()
