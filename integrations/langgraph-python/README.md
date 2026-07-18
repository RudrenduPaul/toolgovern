# toolgovern-integration-langgraph (Python)

Route real [`langchain-ai/langgraph`](https://github.com/langchain-ai/langgraph) (Python) tool
calls through [toolgovern](https://github.com/RudrenduPaul/toolgovern)'s `govern_tool()` gate --
shell, filesystem, network, and credential access evaluated (allow, deny, or require-approval)
before your real tool runs.

The toolgovern core is live on PyPI as `toolgovern-cli` (`pip install toolgovern-cli`; the module
you import stays `toolgovern`). This adapter package is not yet
published there; install it from source, which pulls the PyPI core in as a normal dependency:

```bash
git clone https://github.com/RudrenduPaul/toolgovern.git
cd toolgovern
pip install -e integrations/langgraph-python
```

See [the root toolgovern README](https://github.com/RudrenduPaul/toolgovern) for why runtime
tool-call governance matters right now.

## Why this package exists (and why it isn't the JS adapter with the file extension changed)

This project already ships `integrations/langgraph` for **LangGraph.js**
(`langchain-ai/langgraphjs`). That package wraps at tool-definition time because LangGraph.js's
`ToolNode` constructor only accepts `{name, tags, handleToolErrors}` -- there is no interception
hook inside the node itself.

**`langchain-ai/langgraph` (the separately maintained Python package) is different.** Confirmed by
reading the real, installed source (`langgraph==1.2.9`, `langgraph-prebuilt==1.1.0` at the time of
writing) at `langgraph/prebuilt/tool_node.py`:

```python
class ToolNode(RunnableCallable):
    def __init__(
        self,
        tools: Sequence[BaseTool | Callable],
        *,
        name: str = "tools",
        tags: list[str] | None = None,
        handle_tool_errors: ... = _default_handle_tool_errors,
        messages_key: str = "messages",
        wrap_tool_call: ToolCallWrapper | None = None,
        awrap_tool_call: AsyncToolCallWrapper | None = None,
    ) -> None: ...
```

`wrap_tool_call` is a first-class, public `ToolNode` constructor parameter -- not a private
attribute, not something reached by monkey-patching. Every real LangGraph GitHub issue this
project has validated (`langchain-ai/langgraph` #8026, #7687, #7178, #8169) is filed against
exactly this package, so this hook is the integration point that actually matters. See
[`docs/root-cause.md`](./docs/root-cause.md) for the per-issue verdict.

## Two entry points, one gate underneath

Both routes call the identical `toolgovern.govern_tool()` classifier. Neither monkey-patches
`ToolNode`, `BaseTool`, or any LangChain/LangGraph internal.

### 1. `governed_wrap_tool_call` / `governed_tool_node` -- the primary, LangGraph-native route

```python
from langgraph.prebuilt import ToolNode
from toolgovern import GovernToolOptions, load_policy
from toolgovern_integration_langgraph import governed_wrap_tool_call, governed_tool_node

policy = load_policy("./toolgovern.policy.yml")
options = GovernToolOptions.from_policy(policy, agent_id="research-sub", session_id="demo-session")

# Option A: build the wrap_tool_call yourself
tool_node = ToolNode(my_tools, wrap_tool_call=governed_wrap_tool_call(options))

# Option B: one-call convenience
tool_node = governed_tool_node(my_tools, options)
```

Every call the `ToolNode` dispatches -- to any tool in `my_tools` -- is routed through
toolgovern's classifier before LangGraph's own `execute()` runs the tool. Because the wrapper
receives the call's live `ToolCallRequest` (with `.state` and `.runtime`), you can also derive
`session_id`/`agent_id` per call instead of pinning them statically:

```python
tool_node = governed_tool_node(
    my_tools,
    options,
    session_id_from_runtime=lambda runtime: runtime.config.get("configurable", {}).get("thread_id"),
)
```

### 2. `governed_tool` / `governed_tools` -- tool-definition-boundary route

For call sites that don't build a `ToolNode` directly (`create_react_agent(..., tools=...)`,
`bind_tools()`), wrap the tools themselves -- the same approach the LangGraph.js adapter uses:

```python
from toolgovern_integration_langgraph import governed_tools

governed = governed_tools(my_tools, options)
agent = create_react_agent(model, tools=governed)
```

## Denial behavior

A `deny` decision raises `toolgovern.ToolGovernDenialError` before the real tool ever executes --
that invariant is unconditional and verified by this package's tests. What that exception turns
**into** by the time your graph's caller sees it depends on `handle_tool_errors`, verified against
the currently installed `langgraph==1.2.9`:

- `ToolNode`'s own **default** (`handle_tool_errors` left unset -- `_default_handle_tool_errors`)
  only recognizes LangChain's `ToolInvocationError` and re-raises everything else. With no
  explicit configuration, a denial propagates out of the graph invocation as a **raised
  exception**, not a chat-visible error message. This is a real, current behavior difference from
  older LangGraph releases -- don't assume otherwise without checking.
- Passing `handle_tool_errors=True` (the bool literal) explicitly makes `ToolNode` catch
  `ToolGovernDenialError` and convert it into a `ToolMessage` with `status="error"`, so the agent
  sees a normal tool-error turn instead of a crash.

Either way, the tool body never runs on a denied call. Choose `handle_tool_errors=True` explicitly
if you want denials to show up as an in-conversation error message rather than a raised exception.

## What this does not claim

- This package does not add a graph-level `ApprovalNode` to LangGraph, and it does not change
  upstream LangGraph/LangGraph-prebuilt code at all -- it is a gate applied from outside, at a
  public extension point the framework already exposes.
- toolgovern's own durable, resumable approval registry (`toolgovern.approval`) already implements
  the pending-decision contract (server-generated id, args-digest re-classification on edit,
  fail-closed on an unrecognized resume id) that came out of the `#8026`/`#8169` discussion. This
  package plugs LangGraph tool calls into that existing registry; it does not reimplement it.
- "Allowed" means "checked against the current rule set," not "guaranteed safe." See
  `docs/security-model.md` in the repository root.

See [`docs/root-cause.md`](./docs/root-cause.md) for the full per-issue PASS/PARTIAL/FAIL
analysis, and the [main toolgovern documentation](https://github.com/RudrenduPaul/toolgovern) for
the middleware itself, the rule pack, and the trace format spec.

## Development

```bash
cd integrations/langgraph-python
pip install -e "../../python[dev]"   # the toolgovern core, editable
pip install -e ".[dev]"
pytest
```

## License

Apache 2.0. See [LICENSE](https://github.com/RudrenduPaul/toolgovern/blob/main/LICENSE).
