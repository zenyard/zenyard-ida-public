"""
Allows running code that accesses IDA's API from async.

Utilities:
- `run` - call a sync function from async.
- `run_ui` - modify UI from async.
- `AsyncCallback` - make async function callable from sync.
- `hook` - apply IDA hooks from async.
"""

import asyncio
import contextvars
import typing as ty
from contextlib import asynccontextmanager
from dataclasses import dataclass
import threading

import anyio
import ida_hexrays
import ida_kernwin
import typing_extensions as tye

from decompai_ida import logger

_R = ty.TypeVar("_R", covariant=True)
_P = tye.ParamSpec("_P")

# Keeps queued tasks, allowing to manually execute them using
# `execute_queued_tasks_sync`.
# The dict is used as queue allowing fast removals. Note that insertion order
# is guaranteed since Python 3.7.
_queued_tasks_lock = threading.Lock()
_queued_tasks = dict[ty.Callable, None]()


async def run(
    func: ty.Callable[_P, _R], *args: _P.args, **kwargs: _P.kwargs
) -> _R:
    return await _run_in_main(lambda: func(*args, **kwargs))


async def run_ui(
    func: ty.Callable[_P, _R], *args: _P.args, **kwargs: _P.kwargs
) -> _R:
    """
    Like `run`, but function is called sooner and without access to DB.

    Only suitable for updating UI.
    """
    return await _run_in_main(
        lambda: func(*args, **kwargs), flags=ida_kernwin.MFF_FAST
    )


def execute_queued_tasks_sync():
    """
    Immediately execute all tasks queued using `run` or `run_ui`.

    This must be done in context of IDA's main thread, with `MFF_WRITE` flag.
    It can be used periodically during long running foreground operations to
    unblock background tasks.
    """
    global _queued_tasks

    while True:
        with _queued_tasks_lock:
            taken_tasks = _queued_tasks
            _queued_tasks = {}

        if len(taken_tasks) == 0:
            break

        for queud_task in taken_tasks:
            try:
                queud_task()
            except Exception as ex:
                logger.warning("Queued task failed", exc_info=ex)


def _queue_task(func: ty.Callable):
    with _queued_tasks_lock:
        _queued_tasks[func] = None


def _remove_from_queue(func: ty.Callable):
    with _queued_tasks_lock:
        if func in _queued_tasks:
            del _queued_tasks[func]


@dataclass
class _Success(ty.Generic[_R]):
    value: _R


@dataclass
class _Failure:
    ex: Exception


@dataclass
class _Missing:
    pass


async def _run_in_main(
    func: ty.Callable[[], _R], flags=ida_kernwin.MFF_WRITE
) -> _R:
    output: ty.Union[_Success, _Failure, _Missing] = _Missing()
    done = anyio.Event()
    set_done = AsyncCallback(done.set)
    cancelled = False
    context = contextvars.copy_context()

    def perform():
        nonlocal output, cancelled
        if cancelled:
            return

        # Avoid re-running
        cancelled = True
        _remove_from_queue(perform)

        try:
            output = _Success(context.run(func))
        except Exception as ex:
            output = _Failure(ex)
        finally:
            set_done()

    _queue_task(perform)
    _execute_sync(perform, flags | ida_kernwin.MFF_NOWAIT)
    try:
        await done.wait()
    except:
        cancelled = True
        raise

    assert isinstance(output, (_Success, _Failure)), "missing output"

    if isinstance(output, _Success):
        return output.value
    elif isinstance(output, _Failure):
        raise output.ex
    else:
        _: tye.Never = output


# Patched in tests.
_execute_sync = ida_kernwin.execute_sync


_P = tye.ParamSpec("_P")


class AsyncCallback(ty.Generic[_P]):
    """
    Allows calling async code from IDA's thread.

    set_event_loop must be called initially from an async context. Calling does not block caller
    thread, only schedules call on event loop.
    """

    _context: contextvars.Context
    _callback: ty.Callable[_P, ty.Union[ty.Awaitable[None], None]]

    @classmethod
    def set_event_loop(cls):
        cls._loop = asyncio.get_running_loop()

    @classmethod
    def get_event_loop(cls) -> asyncio.AbstractEventLoop:
        return cls._loop

    def __init__(
        self, callback: ty.Callable[_P, ty.Union[ty.Awaitable[None], None]]
    ):
        self._context = contextvars.copy_context()
        self._callback = callback

    def __call__(self, *args: _P.args, **kwargs: _P.kwargs) -> None:
        async def run():
            result = self._context.run(self._callback, *args, **kwargs)
            if result is not None:
                await result

        try:
            asyncio.run_coroutine_threadsafe(run(), loop=self.get_event_loop())
        except RuntimeError:
            # Event loop closed
            pass


class _Hooks(ty.Protocol):
    def hook(self) -> bool: ...
    def unhook(self) -> bool: ...


_all_hooks = set[_Hooks]()


@asynccontextmanager
async def install_hooks(hooks: _Hooks):
    log = logger.bind(hooks_type=type(hooks).__name__)
    success = await run_ui(hooks.hook)
    if not success:
        raise Exception(f"Hooking {hooks} failed")
    _all_hooks.add(hooks)
    await log.ainfo("Hooks installed")
    try:
        yield
    finally:
        if hooks not in _all_hooks:
            # Already uninstalled via `unhook_all...`
            return

        with anyio.CancelScope(shield=True):
            success = await run_ui(hooks.unhook)
            if not success:
                raise Exception(f"Unhooking {hooks} failed")
            if hooks in _all_hooks:
                _all_hooks.remove(hooks)
            await log.ainfo("Hooks uninstalled")


def unhook_all_hexrays_sync():
    hexrays_hooks = [
        hooks
        for hooks in _all_hooks
        if isinstance(hooks, ida_hexrays.Hexrays_Hooks)
    ]

    for hooks in hexrays_hooks:
        hooks.unhook()
        _all_hooks.remove(hooks)


def unhook_all_sync():
    for hooks in _all_hooks:
        hooks.unhook()
    _all_hooks.clear()


@asynccontextmanager
async def install_action(
    *,
    action_id: str,
    label: str,
    handler: ida_kernwin.action_handler_t,
    shortcut: ty.Optional[str] = None,
    tooltip: ty.Optional[str] = None,
    icon: int = -1,
    flags: int = 0,
):
    log = logger.bind(action_id=action_id)
    action_desc = ida_kernwin.action_desc_t(
        action_id,
        label,
        handler,
        shortcut,  # type: ignore
        tooltip,  # type: ignore
        icon,
        flags,
    )
    success = await run_ui(ida_kernwin.register_action, action_desc)
    if not success:
        raise Exception(f"Registering action {action_id} failed")
    await log.ainfo("Action installed")
    try:
        yield
    finally:
        with anyio.CancelScope(shield=True):
            success = await run_ui(ida_kernwin.unregister_action, action_id)
            if not success:
                raise Exception(f"Unregistering action {action_id} failed")
            await log.ainfo("Action uninstalled")
