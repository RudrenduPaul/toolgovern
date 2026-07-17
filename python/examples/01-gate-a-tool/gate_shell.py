"""Example 1: gate a real tool with govern_tool().

Wraps a minimal shell-executing tool with toolgovern's classifier. A benign command executes
normally; a dangerous one is denied before subprocess.run() ever gets called -- the classifier
evaluates the argument string, not the tool's name, so this works regardless of what you call
your own shell tool.

Run: python3 examples/01-gate-a-tool/gate_shell.py
"""

import subprocess

from toolgovern import (
    GovernToolOptions,
    ScopeDeclaration,
    ToolDefinition,
    ToolGovernDenialError,
    govern_tool,
)


def run_shell(args):
    result = subprocess.run(
        args["command"], shell=True, capture_output=True, text=True, timeout=10
    )
    return result.stdout.strip()


def main():
    shell_tool = ToolDefinition(name="shell", execute=run_shell)

    # An empty scope: no network, no filesystem, no credentials declared. Combined with the
    # default policy (defaultDecision="allow"), this only affects rules that check declared
    # scope (TG02/TG03/TG04) -- the TG01 shell-risk rules evaluate the command text directly
    # and don't need a scope grant to fire.
    gated_shell = govern_tool(shell_tool, GovernToolOptions(scope=ScopeDeclaration()))

    print("Running a benign command through the gate...")
    output = gated_shell.execute({"command": "echo 'hello from a governed tool call'"})
    print(f"  -> allowed, output: {output!r}")

    print("\nAttempting a dangerous command through the same gate...")
    try:
        gated_shell.execute({"command": "rm -rf /"})
        print("  -> ERROR: this should have been denied")
    except ToolGovernDenialError as e:
        print(f"  -> denied before execution: {e}")
        print(f"     fired rules: {[r.rule_id for r in e.decision_info.fired_rules]}")


if __name__ == "__main__":
    main()
