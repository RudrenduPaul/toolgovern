# ToolGovern.Net

A faithful .NET port of [ToolGovern](https://github.com/RudrenduPaul/toolgovern)'s core: the
multi-rule risk classifier, the intersection-only scope registry, the signed hash-chained trace,
and the `GovernTool()` pre-execution middleware gate.

This targets Microsoft Agent Framework 1.0 and any other .NET agent runtime that needs a
pre-execution governance gate in front of a tool call. See the repository root README for the
full security model and honest limitations.
