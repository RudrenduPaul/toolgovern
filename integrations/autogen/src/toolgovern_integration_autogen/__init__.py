"""toolgovern-integration-autogen -- routes real Microsoft AutoGen (``autogen-agentchat`` /
``autogen-core`` / ``autogen-ext``) tool and code-execution calls through toolgovern's
``govern_tool()`` gate before they reach AutoGen's own executor/tool-dispatch call sites.

Two wrappers, addressing two different real call sites:

- ``GovernedCodeExecutor`` (``code_executor.py``) wraps any ``autogen_core.code_executor.
  CodeExecutor`` (``LocalCommandLineCodeExecutor``, ``DockerCommandLineCodeExecutor``,
  ``JupyterCodeExecutor``, ...) so every ``CodeBlock`` is classified before the real executor
  runs it. This is the direct fix for the flagship
  `microsoft/autogen#7462 <https://github.com/microsoft/autogen/issues/7462>`_ report.
- ``governed_autogen_tool()`` / ``governed_autogen_tools()`` (``tool.py``) wrap any
  ``autogen_core.tools.Tool`` so every ``run_json()`` call is classified before the tool's real
  ``run()`` executes -- the same dispatch point ``autogen_core.tool_agent.ToolAgent`` and
  ``AssistantAgent`` both use.

Everything importable from ``toolgovern`` itself (``GovernToolOptions``, ``ScopeDeclaration``,
``ToolGovernDenialError``, ``ScopeRegistry``, ``load_policy``, ...) is the real dependency this
package builds on top of -- see the ``toolgovern`` core's own README for that API.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .code_executor import DEFAULT_TOOL_NAME, GovernedCodeExecutor
from .tool import governed_autogen_tool, governed_autogen_tools

__all__ = [
    "__version__",
    "GovernedCodeExecutor",
    "DEFAULT_TOOL_NAME",
    "governed_autogen_tool",
    "governed_autogen_tools",
]
