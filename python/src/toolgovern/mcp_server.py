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

_STATIC_FALLBACK_DESCRIPTION = (
    "Run the toolgovern-cli command-line tool with the given argument list "
    "and return its output. toolgovern-cli validates governance policy "
    "files and audits signed local trace logs of allow/deny/require-"
    "approval decisions made by toolgovern's runtime tool-call gate. Pass "
    "the same arguments you would give the `toolgovern-cli` command on the "
    'command line, e.g. run(args=["validate", "./toolgovern.policy.yml", '
    '"--json"]).'
)


def _get_cli_help() -> str:
    """Runs `python -m toolgovern.cli --help` to source the tool
    description from the CLI's real, current `--help` text. Returns "" on
    any failure so the caller can fall back to the static description
    instead of crashing at import time."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "toolgovern.cli", "--help"],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return (result.stdout or result.stderr).strip()


def _build_run_description() -> str:
    help_text = _get_cli_help()
    if not help_text:
        return _STATIC_FALLBACK_DESCRIPTION
    return (
        "Run the toolgovern-cli command-line tool with the given argument "
        f"list and return its output.\n\n{help_text}"
    )


# Populated once at import time from the real, installed CLI -- not
# hand-maintained, so it can't silently drift from actual `--help` output.
_RUN_TOOL_DESCRIPTION = _build_run_description()


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
