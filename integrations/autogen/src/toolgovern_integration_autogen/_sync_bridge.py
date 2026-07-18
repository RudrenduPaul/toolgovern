"""Bridges a synchronous callable -- the shape ``toolgovern``'s ``ToolDefinition.execute``
requires (``Callable[[Mapping[str, Any]], Any]``, see ``python/src/toolgovern/middleware/
on_tool_call.py``) -- to a real, ``async def`` AutoGen call: ``CodeExecutor.execute_code_blocks()``
and ``Tool.run_json()`` are both coroutines in every current autogen-core/autogen-ext release.

A plain ``asyncio.run(coro)`` cannot be used for this: every caller of ``run_coroutine_sync()`` in
this package is itself already running inside an active asyncio event loop (an AutoGen agent's own
``execute_code_blocks``/``run_json`` coroutine, which is what calls into ``govern_tool()``'s
synchronous ``execute()`` in the first place), and ``asyncio.run()`` raises ``RuntimeError:
asyncio.run() cannot be called from a running event loop`` in that situation.

The fix used here is the same one the ``toolgovern`` core itself already uses for the analogous
problem -- see ``on_tool_call.py``'s ``_resolve_approval`` (bridges a synchronous approval-handler
timeout) and ``network_egress.py``'s ``_resolve_host_addresses`` (bridges a blocking DNS lookup
with a timeout): run the coroutine to completion on a dedicated worker thread with its own fresh
event loop, then hand the result (or the exact exception it raised) back to the calling thread.

This means the real AutoGen call this bridges to runs on a different OS thread than the one that
scheduled it. For the two call sites this module is used from (a single code block's execution, a
single tool's ``run_json``), that is harmless: neither result depends on thread-local state. The
one honestly-disclosed limitation: a ``CancellationToken`` cancelled from the *original* thread's
event loop after the bridged call has already started may not interrupt the bridged coroutine as
promptly as it would if it were running on the original loop, since the cancellation plumbing
(``CancellationToken.link_future``) is wired to a future that lives on the worker thread's loop,
not the caller's. Ordinary (non-cancelled) execution is unaffected.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any, Coroutine, Dict, TypeVar

T = TypeVar("T")

__all__ = ["run_coroutine_sync"]


def run_coroutine_sync(coro: "Coroutine[Any, Any, T]") -> T:
    """Runs ``coro`` to completion on a dedicated worker thread and returns its result, blocking
    the calling thread until it finishes. Re-raises whatever exception ``coro`` itself raised,
    on the caller's thread, so a denial or a real execution error surfaces exactly as it would
    from a direct ``await``."""
    result_box: Dict[str, T] = {}
    error_box: Dict[str, BaseException] = {}

    def _runner() -> None:
        try:
            result_box["value"] = asyncio.run(coro)
        except BaseException as exc:  # noqa: BLE001 -- re-raised verbatim on the caller's thread below
            error_box["value"] = exc

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    thread.join()

    if "value" in error_box:
        raise error_box["value"]
    return result_box["value"]
