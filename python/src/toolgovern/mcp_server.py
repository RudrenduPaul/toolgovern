"""MCP server (Python): exposes the toolgovern-cli command-line tool to agent
runtimes over stdio.

Requires the `mcp` extra (`pip install "toolgovern-cli[mcp]"`). Started via
the `toolgovern-mcp` console script (installed by `python/pyproject.toml`'s
`[project.scripts]`).

This is a generic subprocess wrapper, not a per-subcommand tool set: a
single `run` tool shells out to `python -m toolgovern.cli <args>` (invoked by
module rather than by looking up the `toolgovern-cli` binary on PATH, so it
works the same whether or not the console script entry point is installed)
and returns the result. Wrapping the CLI this way means the tool stays in
sync with `validate`, `audit`, and any future subcommand without a matching
MCP tool hand-written for each one.

Every failure path (the subprocess never starting, timing out, exiting
non-zero, or printing non-JSON stdout) is caught and returned as a
`{"error": ...}` dict. This tool handler must never raise -- an uncaught
exception here would surface as a raw MCP protocol error instead of a
readable result.

Uses `mcp.server.MCPServer`, the official SDK's current high-level server
class (`mcp` 2.0.0+) -- earlier `mcp` 1.x releases exposed the same
`.tool()`/`.run()` pattern under `mcp.server.fastmcp.FastMCP`, which was
removed in the 2.0.0 release.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

from mcp.server import MCPServer

_TIMEOUT_SECONDS = 60

_RUN_TOOL_DESCRIPTION = (
    "Executes one toolgovern-cli subcommand (validate, audit, or init) and returns its "
    "structured result. Call this to check a governance policy file for errors before "
    "deploying it, to forensically inspect a signed trace log of the allow/deny/"
    "require-approval decisions toolgovern's runtime tool-call gate already made for an "
    "agent run, or to scaffold a starter policy/integration file for a detected framework "
    "(open-multi-agent or LangGraph). This tool does not itself gate live tool calls -- that "
    "happens inside the governed agent process via the toolgovern library -- it only "
    "validates, audits, and scaffolds around that gate.\n\n"
    "No API key or network access is required; everything runs locally against files you "
    "supply. 'validate' and 'audit' are strictly read-only (they only read the policy or "
    "trace file given). 'init' writes a new integration file to disk and will refuse to "
    "overwrite an existing one unless '--force' is passed. 'audit --verify-chain' "
    "cryptographically checks the trace file's hash chain for tampering; if the trace was "
    "written with a TraceWriter secretKey, pass '--key-file <path>' to verify the "
    "hmac-sha256 signatures, otherwise unkeyed sha256 entries verify without it. This "
    "handler never raises -- a launch failure, timeout, non-zero exit, or non-JSON stdout is "
    "always returned as {\"error\": ...} instead of an exception.\n\n"
    "Parameter `args` is the literal argv you would type after `toolgovern-cli` on the "
    "command line, as a list of strings. Real examples: run(args=[\"validate\", "
    "\"./toolgovern.policy.yml\", \"--json\"]) to check a policy file is well-formed; "
    "run(args=[\"audit\", \"./toolgovern-trace.jsonl\", \"--decision\", \"deny\", "
    "\"--json\"]) to list every denied tool call in a trace log; run(args=[\"audit\", "
    "\"./toolgovern-trace.jsonl\", \"--agent\", \"research-sub\", \"--since\", \"24h\", "
    "\"--verify-chain\", \"--json\"]) to audit one agent's recent decisions with tamper "
    "verification; run(args=[\"init\", \"langgraph\", \"--policy\", "
    "\"./toolgovern.policy.yml\", \"--json\"]) to scaffold a LangGraph integration. Always "
    "include '--json' -- without it the CLI prints human-formatted text instead of a "
    "parseable object.\n\n"
    "With '--json', the CLI emits exactly one JSON object to stdout (never split across "
    "stdout/stderr): {\"ok\": true, \"command\": ..., \"data\": {...}} on success, where "
    "'data' holds the full result (e.g. matched/total counts and TraceEntry rows for "
    "'audit'), or {\"ok\": false, \"command\": ..., \"error\": ...} on failure. This Python "
    "wrapper further normalizes that into {\"result\": <parsed JSON>} on a zero exit, or "
    "{\"returncode\", \"stdout\", \"stderr\"} if stdout wasn't valid JSON (e.g. '--json' was "
    "omitted), or {\"error\": ..., \"returncode\": ...} on a non-zero exit. Pass "
    "run(args=[\"--help\"]) or run(args=[\"<subcommand>\", \"--help\"]) for the CLI's own "
    "current usage text."
)


def build_app() -> MCPServer:
    app = MCPServer("toolgovern")

    @app.tool(description=_RUN_TOOL_DESCRIPTION)
    def run(args: list[str]) -> dict[str, Any]:
        try:
            result = subprocess.run(
                [sys.executable, "-m", "toolgovern.cli", *args],
                capture_output=True,
                text=True,
                timeout=_TIMEOUT_SECONDS,
            )
        except OSError as error:
            return {"error": f"failed to launch the toolgovern-cli CLI: {error}"}
        except subprocess.TimeoutExpired:
            return {"error": f"toolgovern-cli timed out after {_TIMEOUT_SECONDS}s"}

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if result.returncode != 0:
            return {
                "error": stderr or stdout or f"toolgovern-cli exited with code {result.returncode}",
                "returncode": result.returncode,
            }

        if not stdout:
            return {"returncode": result.returncode, "stdout": "", "stderr": stderr}

        try:
            return {"result": json.loads(stdout)}
        except json.JSONDecodeError:
            # Not every subcommand supports --json (or the caller didn't
            # pass it) -- return the raw text rather than treating this as
            # an error.
            return {"returncode": result.returncode, "stdout": stdout, "stderr": stderr}

    return app


def main() -> None:
    """Entry point for the `toolgovern-mcp` console script."""
    app = build_app()
    app.run(transport="stdio")


if __name__ == "__main__":
    main()
