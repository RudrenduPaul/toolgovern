"""Tests for the tool-definition-boundary entry point: ``governed_tool`` / ``governed_tools`` --
the same wrapping approach ``integrations/langgraph`` (the LangGraph.js adapter) uses, ported to a
real ``langchain_core.tools.BaseTool``. Exercised both directly (``.invoke()``) and through a real
``ToolNode`` with no ``wrap_tool_call`` at all, proving these wrapped tools are a genuine drop-in
``BaseTool`` replacement.
"""

from typing import Annotated, TypedDict

import pytest
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import BaseTool, tool
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from toolgovern import GovernToolOptions, ScopeDeclaration, ToolGovernDenialError
from toolgovern_integration_langgraph import governed_tool, governed_tools


class _State(TypedDict):
    messages: Annotated[list, add_messages]


class TestGovernedToolDirectInvoke:
    def test_returns_a_real_base_tool_with_same_identity(self):
        @tool
        def run_shell(command: str) -> str:
            """Runs a shell command."""
            return f"ran: {command}"

        options = GovernToolOptions(scope=ScopeDeclaration())
        governed = governed_tool(run_shell, options)

        assert isinstance(governed, BaseTool)
        assert governed.name == run_shell.name
        assert governed.description == run_shell.description

    def test_denied_call_raises_and_never_executes(self):
        calls = []

        @tool
        def run_shell(command: str) -> str:
            """Runs a shell command. Never actually executed for a denied call."""
            calls.append(command)
            return f"ran: {command}"

        options = GovernToolOptions(scope=ScopeDeclaration())
        governed = governed_tool(run_shell, options)

        with pytest.raises(ToolGovernDenialError):
            governed.invoke({"command": "rm -rf /"})

        assert calls == []

    def test_allowed_call_passes_through_unchanged(self):
        calls = []

        @tool
        def run_shell(command: str) -> str:
            """Runs a shell command."""
            calls.append(command)
            return f"ran: {command}"

        options = GovernToolOptions(scope=ScopeDeclaration())
        governed = governed_tool(run_shell, options)

        result = governed.invoke({"command": "ls -la"})

        assert result == "ran: ls -la"
        assert calls == ["ls -la"]

    def test_governed_tools_wraps_a_whole_sequence(self):
        @tool
        def tool_a(x: str) -> str:
            """A."""
            return x

        @tool
        def tool_b(y: str) -> str:
            """B."""
            return y

        options = GovernToolOptions(scope=ScopeDeclaration())
        governed = governed_tools([tool_a, tool_b], options)

        assert [t.name for t in governed] == ["tool_a", "tool_b"]
        assert governed[0].invoke({"x": "hi"}) == "hi"


class TestGovernedToolInsideRealToolNode:
    """A governed_tool()-wrapped tool must be a drop-in ToolNode member even with NO
    wrap_tool_call configured at all -- this is the point of wrapping at the tool-definition
    boundary rather than the ToolNode constructor."""

    def _compiled_graph_with(self, node: ToolNode):
        graph = StateGraph(_State)
        graph.add_node("tools", node)
        graph.add_edge(START, "tools")
        graph.add_edge("tools", END)
        return graph.compile()

    def test_denied_call_through_plain_tool_node(self):
        calls = []

        @tool
        def delete_file(operation: str, path: str) -> str:
            """Deletes a file. Never actually executed for a denied call."""
            calls.append((operation, path))
            return f"deleted {path}"

        options = GovernToolOptions(scope=ScopeDeclaration())
        # handle_tool_errors=True (the bool) explicitly, since the currently installed langgraph
        # (1.2.9)'s own DEFAULT handler only converts ToolInvocationError into an error
        # ToolMessage and re-raises everything else -- see
        # test_governed_wrap_tool_call.py::test_default_handle_tool_errors_lets_denial_propagate_as_a_raised_exception
        # for the same behavior proven directly against ToolNode's real default.
        node = ToolNode(governed_tools([delete_file], options), handle_tool_errors=True)
        compiled = self._compiled_graph_with(node)

        msg = AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "delete_file",
                    "args": {"operation": "delete", "path": "/etc/passwd"},
                    "id": "1",
                }
            ],
        )
        result = compiled.invoke({"messages": [msg]})

        tool_message = result["messages"][-1]
        assert isinstance(tool_message, ToolMessage)
        assert tool_message.status == "error"
        assert "TG02-delete-outside-scope" in tool_message.content
        assert calls == []

    def test_allowed_call_through_plain_tool_node(self):
        calls = []

        @tool
        def echo(text: str) -> str:
            """Echoes text."""
            calls.append(text)
            return f"echo:{text}"

        options = GovernToolOptions(scope=ScopeDeclaration())
        node = ToolNode(governed_tools([echo], options))
        compiled = self._compiled_graph_with(node)

        msg = AIMessage(content="", tool_calls=[{"name": "echo", "args": {"text": "hi"}, "id": "1"}])
        result = compiled.invoke({"messages": [msg]})

        tool_message = result["messages"][-1]
        assert tool_message.status != "error"
        assert tool_message.content == "echo:hi"
        assert calls == ["hi"]
