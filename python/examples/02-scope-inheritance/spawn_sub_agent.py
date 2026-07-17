"""Example 2: default-deny scope inheritance across a coordinator/sub-agent pair.

A sub-agent's granted scope is the INTERSECTION of what it requests and what its coordinator's
own effective scope actually covers -- never a union, and never an implicit default-allow. This
script spawns a sub-agent that asks for more than its coordinator has, and shows the excess
request gets silently dropped, then demonstrates that a call to the denied resource is refused.

Run: python3 examples/02-scope-inheritance/spawn_sub_agent.py
"""

from toolgovern import (
    GovernToolOptions,
    ScopeDeclaration,
    ScopeRegistry,
    SpawnSubAgentParams,
    ToolDefinition,
    ToolGovernDenialError,
    govern_tool,
)


def read_file(args):
    return f"<contents of {args['path']}>"


def main():
    registry = ScopeRegistry()

    # The coordinator's own scope: only /workspace, no /etc.
    registry.register_root_agent(
        "coordinator-1", "session-1", ScopeDeclaration(filesystem=["/workspace"])
    )

    # The sub-agent asks for BOTH /workspace and /etc.
    sub_record = registry.spawn_sub_agent(
        SpawnSubAgentParams(
            coordinator_id="coordinator-1",
            sub_agent_id="research-sub",
            session_id="session-1",
            requested_scope=ScopeDeclaration(filesystem=["/workspace", "/etc"]),
        )
    )

    print("Sub-agent requested:", list(sub_record.requested_scope.filesystem))
    print("Sub-agent was granted:", list(sub_record.granted_scope.filesystem))
    print("(/etc was silently dropped -- the coordinator never had it to give.)\n")

    read_tool = ToolDefinition(name="read_file", execute=read_file)
    gated_read = govern_tool(
        read_tool,
        GovernToolOptions(
            scope=sub_record.requested_scope,  # what the sub-agent itself declares
            agent_id="research-sub",
            coordinator_id="coordinator-1",
            scope_registry=registry,
        ),
    )

    print("Reading a file inside the granted scope...")
    result = gated_read.execute({"path": "/workspace/notes.md", "operation": "read"})
    print(f"  -> allowed: {result}")

    print("\nAttempting to read a file the coordinator never granted (/etc/passwd)...")
    try:
        gated_read.execute({"path": "/etc/passwd", "operation": "read"})
        print("  -> ERROR: this should have been denied")
    except ToolGovernDenialError as e:
        print(f"  -> denied: {e}")


if __name__ == "__main__":
    main()
