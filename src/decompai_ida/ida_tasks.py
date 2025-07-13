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

import anyio
import ida_kernwin
import typing_extensions as tye

from decompai_ida import logger

_R = ty.TypeVar("_R", covariant=True)
_P = tye.ParamSpec("_P")


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
        nonlocal output
        if cancelled:
            return
        try:
            output = _Success(context.run(func))
        except Exception as ex:
            output = _Failure(ex)
        finally:
            set_done()

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
        success = await run_ui(hooks.unhook)
        if not success:
            raise Exception(f"Unhooking {hooks} failed")
        if hooks in _all_hooks:
            _all_hooks.remove(hooks)
        await log.ainfo("Hooks uninstalled")


def unhook_all_sync():
    for hooks in _all_hooks:
        hooks.unhook()
    _all_hooks.clear()
