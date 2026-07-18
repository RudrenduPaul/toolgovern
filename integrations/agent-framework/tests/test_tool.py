"""Real tests for governed_function_tool() against the real agent_framework.FunctionTool.

No mocking of agent_framework or toolgovern -- these construct a real FunctionTool via the
wrapper and call its real (async) invoke(), asserting on real classifier decisions.
"""

from __future__ import annotations

import pytest
from agent_framework import FunctionTool
from toolgovern import GovernToolOptions, ScopeDeclaration, ToolGovernDenialError

from toolgovern_integration_agent_framework import governed_function_tool

_executed_commands: list[str] = []


def run_shell(command: str) -> str:
    """Run a shell command (test double -- records instead of actually executing)."""
    _executed_commands.append(command)
    return f"ran: {command}"


@pytest.fixture(autouse=True)
def _clear_executed_commands():
    _executed_commands.clear()
    yield
    _executed_commands.clear()


def _tool(**overrides) -> FunctionTool:
    options = GovernToolOptions(scope=ScopeDeclaration(), agent_id="test-agent", **overrides)
    return governed_function_tool(run_shell, options, description="Run a shell command.")


def test_returns_a_real_function_tool():
    tool = _tool()
    assert isinstance(tool, FunctionTool)
    assert tool.name == "run_shell"
    assert tool.description == "Run a shell command."


@pytest.mark.asyncio
async def test_allowed_call_reaches_the_real_function():
    tool = _tool()

    result = await tool.invoke(arguments={"command": "ls -la"})

    assert _executed_commands == ["ls -la"]
    # invoke() parses the raw return value into Content by default; the tool's real string
    # result should be present somewhere in the parsed output.
    assert any("ran: ls -la" in str(item) for item in result)


@pytest.mark.asyncio
async def test_classified_risky_call_is_denied_before_the_real_function_runs():
    tool = _tool()

    with pytest.raises(ToolGovernDenialError):
        await tool.invoke(arguments={"command": "rm -rf /"})

    # The real function must never have been called.
    assert _executed_commands == []


@pytest.mark.asyncio
async def test_skip_parsing_still_gates_the_call():
    """Confirms the gate applies regardless of the invoke()-level parsing mode, since it lives
    inside the wrapped callable, not in any invoke()-level branch."""
    options = GovernToolOptions(scope=ScopeDeclaration(), agent_id="test-agent")
    tool = governed_function_tool(run_shell, options, description="Run a shell command.")

    with pytest.raises(ToolGovernDenialError):
        await tool.invoke(arguments={"command": "rm -rf /"}, skip_parsing=True)
    assert _executed_commands == []

    raw_result = await tool.invoke(arguments={"command": "echo hi"}, skip_parsing=True)
    assert raw_result == "ran: echo hi"
    assert _executed_commands == ["echo hi"]


@pytest.mark.asyncio
async def test_multi_parameter_schema_is_inferred_from_the_real_function():
    """Confirms FunctionTool's schema inference sees the real function's parameters (names,
    types, defaults) through the wrapper, not the wrapper's own **kwargs signature -- and that a
    model-style call using that schema still reaches the real function with the right values."""

    def move_file(source: str, destination: str, overwrite: bool = False) -> str:
        return f"moved {source} -> {destination} (overwrite={overwrite})"

    options = GovernToolOptions(scope=ScopeDeclaration(filesystem=["/workspace"]), agent_id="test-agent")
    tool = governed_function_tool(move_file, options, description="Move a file.")

    schema = tool.parameters()
    assert set(schema["properties"].keys()) == {"source", "destination", "overwrite"}
    assert schema["properties"]["overwrite"]["default"] is False

    result = await tool.invoke(
        arguments={"source": "/workspace/a.txt", "destination": "/workspace/b.txt"}
    )
    assert any("moved /workspace/a.txt -> /workspace/b.txt (overwrite=False)" in str(item) for item in result)


@pytest.mark.asyncio
async def test_require_approval_fails_closed_with_no_handler():
    """A tool call the classifier marks require-approval (write outside declared scope) with no
    on_approval_required handler wired must fail closed (deny), never silently allow -- matching
    toolgovern's own documented default."""

    def write_file(path: str, operation: str) -> str:
        return f"wrote {path}"

    options = GovernToolOptions(scope=ScopeDeclaration(filesystem=["/workspace"]), agent_id="test-agent")
    tool = governed_function_tool(write_file, options, description="Write a file.")

    with pytest.raises(ToolGovernDenialError):
        await tool.invoke(arguments={"path": "/etc/passwd", "operation": "write"})
