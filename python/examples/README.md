# toolgovern (Python) examples

Install the library first (from PyPI, or `pip install -e .` from a clone of this repo's
`python/` directory), then run any example directly.

```bash
pip install toolgovern
python3 examples/01-gate-a-tool/gate_shell.py
python3 examples/02-scope-inheritance/spawn_sub_agent.py
python3 examples/03-verify-audit-trail/verify_trace.py
```

| Example                                   | What it demonstrates                                                                                                                                                   |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `01-gate-a-tool/gate_shell.py`            | Wrapping a real tool with `govern_tool()` and watching a benign call succeed and a dangerous one get denied before it executes                                         |
| `02-scope-inheritance/spawn_sub_agent.py` | `ScopeRegistry` default-deny inheritance: a sub-agent never receives more than its coordinator actually has, even when it asks for more                                |
| `03-verify-audit-trail/verify_trace.py`   | Writing a signed trace (both the default unkeyed and the optional HMAC-keyed modes) and verifying it with `verify_chain()`, including a tamper-detection demonstration |

Each script is self-contained and prints its own output -- read the comments inline for what
each step is proving.
