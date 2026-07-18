"""Tests for the primary, LangGraph-native entry point: ``governed_wrap_tool_call`` /
``governed_tool_node``, wired into a REAL ``langgraph.prebuilt.ToolNode`` inside a REAL compiled
``StateGraph`` -- not a mock of ``ToolNode``.

Each test proves the invariant this package exists for: a call the classifier denies never reaches
the underlying tool's real implementation (verified by a side-effect list staying empty -- these
tests never actually run a destructive command, they run a stand-in tool that WOULD have if it had
been allowed to execute), and a call the classifier allows passes through with an unchanged
result.
"""

from typing import Annotated, TypedDict

import pytest
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from toolgovern import GovernToolOptions, ScopeDeclaration
from toolgovern_integration_langgraph import governed_tool_node, governed_wrap_tool_call


class _State(TypedDict):
    messages: Annotated[list, add_messages]


def _compiled_graph_with(node: ToolNode):
    graph = StateGraph(_State)
    graph.add_node("tools", node)
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    return graph.compile()


def _ai_message(tool_name: str, args: dict, call_id: str = "call-1") -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": tool_name, "args": args, "id": call_id}])


@pytest.fixture
def shell_calls():
    return []


@pytest.fixture
def shell_tool(shell_calls):
    @tool
    def run_shell(command: str) -> str:
        """Runs a shell command. NEVER actually executed by these tests for a denied call --
        that is exactly the invariant under test."""
        shell_calls.append(command)
        return f"ran: {command}"

    return run_shell


class TestGovernedWrapToolCall:
    def test_denied_shell_call_never_reaches_the_real_tool(self, shell_tool, shell_calls):
        options = GovernToolOptions(scope=ScopeDeclaration(), agent_id="agent-a")
        # handle_tool_errors=True (the bool, not ToolNode's own default) is passed explicitly --
        # see test_default_handle_tool_errors_lets_denial_propagate_as_a_raised_exception below
        # for why the *default* handler does NOT convert this into an error ToolMessage in the
        # currently installed langgraph (1.2.9): its default handler only recognizes
        # ToolInvocationError and re-raises everything else, including ToolGovernDenialError.
        node = ToolNode(
            [shell_tool], wrap_tool_call=governed_wrap_tool_call(options), handle_tool_errors=True
        )
        compiled = _compiled_graph_with(node)

        result = compiled.invoke(
            {"messages": [_ai_message("run_shell", {"command": "rm -rf /"})]}
        )

        tool_message = result["messages"][-1]
        assert isinstance(tool_message, ToolMessage)
        assert tool_message.status == "error"
        assert "toolgovern denied" in tool_message.content
        assert "TG01-rm-rf" in tool_message.content
        # The invariant: the real tool body never ran.
        assert shell_calls == []

    def test_allowed_shell_call_passes_through_unchanged(self, shell_tool, shell_calls):
        options = GovernToolOptions(scope=ScopeDeclaration(), agent_id="agent-a")
        node = ToolNode([shell_tool], wrap_tool_call=governed_wrap_tool_call(options))
        compiled = _compiled_graph_with(node)

        result = compiled.invoke({"messages": [_ai_message("run_shell", {"command": "ls -la"})]})

        tool_message = result["messages"][-1]
        assert isinstance(tool_message, ToolMessage)
        assert tool_message.status != "error"
        assert tool_message.content == "ran: ls -la"
        assert shell_calls == ["ls -la"]

    def test_denied_filesystem_call_never_reaches_the_real_tool(self):
        calls = []

        @tool
        def delete_file(operation: str, path: str) -> str:
            """Deletes a file. Never actually executed for a denied call."""
            calls.append((operation, path))
            return f"deleted {path}"

        options = GovernToolOptions(scope=ScopeDeclaration(), agent_id="agent-a")
        node = ToolNode(
            [delete_file],
            wrap_tool_call=governed_wrap_tool_call(options),
            handle_tool_errors=True,
        )
        compiled = _compiled_graph_with(node)

        result = compiled.invoke(
            {
                "messages": [
                    _ai_message("delete_file", {"operation": "delete", "path": "/etc/passwd"})
                ]
            }
        )

        tool_message = result["messages"][-1]
        assert tool_message.status == "error"
        assert "TG02-delete-outside-scope" in tool_message.content
        assert calls == []

    def test_denied_network_call_never_reaches_the_real_tool(self):
        calls = []

        @tool
        def http_get(url: str) -> str:
            """Fetches a URL. Never actually executed for a denied call."""
            calls.append(url)
            return f"fetched {url}"

        # scope.network defaults to False (no declared network access) -- any egress is gated.
        options = GovernToolOptions(scope=ScopeDeclaration(), agent_id="agent-a")
        node = ToolNode(
            [http_get], wrap_tool_call=governed_wrap_tool_call(options), handle_tool_errors=True
        )
        compiled = _compiled_graph_with(node)

        result = compiled.invoke(
            {"messages": [_ai_message("http_get", {"url": "https://example.internal/exfil"})]}
        )

        tool_message = result["messages"][-1]
        assert tool_message.status == "error"
        assert calls == []

    def test_governed_tool_node_convenience_constructor_behaves_identically(
        self, shell_tool, shell_calls
    ):
        options = GovernToolOptions(scope=ScopeDeclaration(), agent_id="agent-a")
        node = governed_tool_node([shell_tool], options, handle_tool_errors=True)
        compiled = _compiled_graph_with(node)

        result = compiled.invoke(
            {"messages": [_ai_message("run_shell", {"command": "rm -rf /"})]}
        )

        assert result["messages"][-1].status == "error"
        assert shell_calls == []

    def test_default_handle_tool_errors_lets_denial_propagate_as_a_raised_exception(
        self, shell_tool, shell_calls
    ):
        """Documents real, verified behavior of the currently installed langgraph (1.2.9): unlike
        older versions, ``ToolNode``'s own DEFAULT ``handle_tool_errors`` (``_default_handle_tool_errors``,
        not the bool ``True``) only converts ``ToolInvocationError`` into an error ``ToolMessage``
        -- every other exception, including ``ToolGovernDenialError``, is re-raised out of
        ``_default_handle_tool_errors`` and propagates out of the graph invocation. The underlying
        tool still never executes either way -- this test proves that half of the invariant while
        being honest that the *shape* of the failure (raised exception vs. error ToolMessage)
        depends on how the caller configures ``handle_tool_errors``, not on this package."""
        options = GovernToolOptions(scope=ScopeDeclaration(), agent_id="agent-a")
        node = ToolNode([shell_tool], wrap_tool_call=governed_wrap_tool_call(options))
        compiled = _compiled_graph_with(node)

        from toolgovern import ToolGovernDenialError

        with pytest.raises(ToolGovernDenialError):
            compiled.invoke({"messages": [_ai_message("run_shell", {"command": "rm -rf /"})]})

        assert shell_calls == []

    def test_session_id_from_runtime_derives_from_thread_id(self):
        """The runtime-derivation hooks exist because a tool-definition-time wrap (like the
        LangGraph.js adapter's) cannot see per-call graph state/runtime at all -- this proves the
        derived session_id actually reaches the classifier's RuleContext by observing it via
        on_decision, which surfaces the GateDecisionInfo including session_id."""
        seen_sessions = []

        @tool
        def noop(x: str) -> str:
            """A no-op tool."""
            return x

        options = GovernToolOptions(
            scope=ScopeDeclaration(),
            agent_id="agent-a",
            session_id="static-fallback",
            on_decision=lambda info: seen_sessions.append(info.session_id),
        )
        node = governed_tool_node(
            [noop],
            options,
            session_id_from_runtime=lambda runtime: runtime.config.get("configurable", {}).get(
                "thread_id"
            ),
        )
        compiled = _compiled_graph_with(node)

        compiled.invoke(
            {"messages": [_ai_message("noop", {"x": "hi"})]},
            config={"configurable": {"thread_id": "thread-42"}},
        )

        assert seen_sessions == ["thread-42"]

    def test_denial_error_type_is_toolgovern_denial_error(self, shell_tool, shell_calls):
        """Confirms the raised exception really is toolgovern.ToolGovernDenialError before
        ToolNode's handle_tool_errors catches it -- not some other exception type that happens to
        also produce an error ToolMessage."""
        from toolgovern import ToolGovernDenialError

        options = GovernToolOptions(scope=ScopeDeclaration(), agent_id="agent-a")
        node = ToolNode(
            [shell_tool],
            wrap_tool_call=governed_wrap_tool_call(options),
            handle_tool_errors=False,
        )
        compiled = _compiled_graph_with(node)

        with pytest.raises(ToolGovernDenialError):
            compiled.invoke({"messages": [_ai_message("run_shell", {"command": "rm -rf /"})]})

        assert shell_calls == []
