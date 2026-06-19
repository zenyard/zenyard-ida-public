"""Main-thread bridge for vendored MCP tools.

ida-pro-mcp's tools are plain synchronous functions decorated with
`@idasync`, which upstream marshals onto IDA's main thread via
`idaapi.execute_sync`. The vendored MCP server runs its HTTP handlers on
their own (non-anyio) threads, so here `@idasync` instead routes each tool
body through the repo's `ida_tasks.run`, executing it on IDA's main thread
via the running anyio event loop.

This module is the only adapted replacement for upstream's `sync.py`; the
vendored `vendor/sync.py` re-exports these names so the api_* modules pick
them up unchanged.

Note: unlike upstream (which aborted tool bodies mid-run via
`sys.setprofile`), a timed-out or cancelled tool here stops being *waited
on* but is never preempted — the main-thread body runs to completion. This
is intentional: preempting IDAPython mid-mutation can corrupt the database.
"""

import asyncio
import concurrent.futures
import functools
import threading
import time
import typing as ty

import idc

from decompai_ida import ida_tasks
from decompai_ida.mcp.vendor.zeromcp import McpToolError
from decompai_ida.mcp.vendor.zeromcp.jsonrpc import (
    RequestCancelledError,
    get_current_cancel_event,
)

if ty.TYPE_CHECKING:
    from decompai_ida.model import Model

_DEFAULT_TOOL_TIMEOUT_SEC = 60.0

# How often the waiting handler thread re-checks for timeout / cancellation
# while the tool body runs on the main thread.
_POLL_INTERVAL_SEC = 0.05


class IDAError(McpToolError):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]


class IDASyncError(Exception):
    pass


class CancelledError(RequestCancelledError):
    """Raised when a request is cancelled via notifications/cancelled."""

    pass


# Thread-local on the IDA main thread: while a synchronized tool body runs,
# holds the batch value in effect before the bridge bumped it to 1. Tools
# decorated with @keep_batch read this via get_pre_call_batch() to restore
# the caller's original state across deferred work. See upstream sync.py.
_main_thread_state = threading.local()


# Model that tool invocations report MCP activity to, so the status bar can
# show the agent is working. Registered by `McpServerTask` while its server is
# up and cleared to None on teardown. Read/written on the event loop thread.
_active_model: ty.Optional["Model"] = None


def set_active_model(model: ty.Optional["Model"]) -> None:
    """Register the model that tool invocations report MCP activity to."""
    global _active_model
    _active_model = model


def get_pre_call_batch() -> ty.Optional[int]:
    """Return the pre-call batch state, or None if not inside a sync body."""
    return getattr(_main_thread_state, "pre_call_batch", None)


def _run_on_main(
    func: ty.Callable[..., ty.Any],
    keep_batch_mode: bool,
    args: tuple,
    kwargs: dict,
) -> ty.Any:
    """Body executed on IDA's main thread via ida_tasks.run.

    Enables batch mode (suppressing UI churn / dialogs) around the tool body,
    exposing the prior state via get_pre_call_batch(), and restores it unless
    the tool opted out with @keep_batch and completed successfully.
    """
    old_batch = idc.batch(1)
    prev_pre_call = getattr(_main_thread_state, "pre_call_batch", None)
    _main_thread_state.pre_call_batch = old_batch
    completed = False
    try:
        result = func(*args, **kwargs)
        completed = True
        return result
    finally:
        if not (completed and keep_batch_mode):
            idc.batch(old_batch)
        _main_thread_state.pre_call_batch = prev_pre_call


async def _run_tool_body(
    f: ty.Callable[..., ty.Any],
    keep_batch_mode: bool,
    args: tuple,
    kwargs: dict,
) -> ty.Any:
    """Run a tool body on IDA's main thread, reporting MCP activity.

    Runs on the event loop (background) thread, where runtime-status mutations
    belong. Reporting is skipped when no model is registered (e.g. before the
    server has fully started).
    """
    model = _active_model
    if model is None:
        return await ida_tasks.run(
            _run_on_main, f, keep_batch_mode, args, kwargs
        )
    with model.report_and_notify_mcp_activity():
        return await ida_tasks.run(
            _run_on_main, f, keep_batch_mode, args, kwargs
        )


def idasync(f: ty.Callable[..., ty.Any]) -> ty.Callable[..., ty.Any]:
    """Run a tool body on the IDA main thread via the anyio event loop.

    Called on an MCP HTTP handler thread; submits the body to the loop with
    `run_coroutine_threadsafe` and waits, honoring per-tool timeout and the
    request's cancel event.
    """

    @functools.wraps(f)
    def wrapper(*args: ty.Any, **kwargs: ty.Any) -> ty.Any:
        timeout = float(
            getattr(f, "__ida_mcp_timeout_sec__", None)
            or _DEFAULT_TOOL_TIMEOUT_SEC
        )
        keep_batch_mode = bool(getattr(f, "__ida_mcp_keep_batch__", False))
        cancel_event = get_current_cancel_event()
        loop = ida_tasks.AsyncCallback.get_event_loop()

        future = asyncio.run_coroutine_threadsafe(
            _run_tool_body(f, keep_batch_mode, args, kwargs),
            loop,
        )

        deadline = time.monotonic() + timeout if timeout > 0 else None
        while True:
            try:
                return future.result(timeout=_POLL_INTERVAL_SEC)
            except concurrent.futures.TimeoutError:
                if cancel_event is not None and cancel_event.is_set():
                    future.cancel()
                    raise CancelledError("Request was cancelled")
                if deadline is not None and time.monotonic() >= deadline:
                    future.cancel()
                    raise IDASyncError(f"Tool timed out after {timeout:.2f}s")

    return wrapper


def tool_timeout(seconds: float) -> ty.Callable[..., ty.Any]:
    """Override a tool's timeout. Apply AFTER @idasync (innermost)."""

    def decorator(func: ty.Callable[..., ty.Any]) -> ty.Callable[..., ty.Any]:
        setattr(func, "__ida_mcp_timeout_sec__", seconds)
        return func

    return decorator


def keep_batch(func: ty.Callable[..., ty.Any]) -> ty.Callable[..., ty.Any]:
    """Skip the post-call batch-mode restore. Apply AFTER @idasync.

    For tools that schedule main-thread work after the body returns (e.g.
    start_process); the tool must arrange its own batch restoration.
    """
    setattr(func, "__ida_mcp_keep_batch__", True)
    return func
