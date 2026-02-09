import typing as ty
from abc import ABC, abstractmethod
from dataclasses import dataclass

import anyio
import structlog
import typing_extensions as tye

from decompai_client import ApiClient, BinariesApi, UserApi
from decompai_client.exceptions import ForbiddenException, UnauthorizedException
from decompai_ida import api, logger
from decompai_ida.broadcast import Broadcast
from decompai_ida.configuration import BadConfigurationFile, PluginConfiguration
from decompai_ida.events import IdaEvent
from decompai_ida.model import CopilotModel, Model
from decompai_ida.wait_box import WaitBox

_T = ty.TypeVar("_T")

_RETRY_SLEEP_INTERVAL_SECONDS = 1


class CriticalTaskError(Exception):
    """Exception raised when a task should stop without retrying."""

    pass


@dataclass(frozen=True)
class StaticConfiguration:
    """
    Hard-coded configuration.
    """

    max_objects_in_revision: int
    max_upload_bytes: int


@dataclass(frozen=True)
class GlobalTaskContext:
    """
    Objects given to all global tasks.
    """

    ida_events: Broadcast[IdaEvent]
    static_config: StaticConfiguration
    api_client: ApiClient


@dataclass(frozen=True)
class TaskContext:
    """
    Objects given to all tasks that run when binary is open.
    """

    model: Model
    copilot_model: CopilotModel
    ida_events: Broadcast[IdaEvent]
    binaries_api: BinariesApi
    user_api: UserApi
    plugin_config: PluginConfiguration
    static_config: StaticConfiguration


class _BaseTask(ABC):
    async def run(self) -> None:
        critical_exception_types = (
            ForbiddenException,
            UnauthorizedException,
            BadConfigurationFile,
            CriticalTaskError,
        )

        with structlog.contextvars.bound_contextvars(task=type(self).__name__):
            while True:
                try:
                    await logger.adebug("Task starting")
                    await self._run()
                    await logger.adebug("Task finished with no error")
                    return
                except critical_exception_types as ex:
                    await logger.awarning(
                        "Task crashed", exc_info=ex, will_retry=False
                    )
                    raise
                except Exception as ex:
                    await logger.awarning(
                        "Task crashed", exc_info=ex, will_retry=True
                    )
                    await anyio.sleep(_RETRY_SLEEP_INTERVAL_SECONDS)

    @abstractmethod
    async def _run(self) -> None: ...


class GlobalTask(_BaseTask):
    """
    A task that runs in background during entire IDA lifetime.
    """

    def __init__(self, global_context: GlobalTaskContext):
        self._ctx = global_context


class Task(_BaseTask):
    """
    A task that runs in background while binary is open, cancelled when binary
    closes.
    """

    def __init__(self, task_context: TaskContext):
        self._ctx = task_context

    async def _retry_api_request_forever(
        self,
        func: ty.Callable[[], ty.Awaitable[_T]],
        *,
        description: ty.Optional[str] = None,
        retry_delay: int = 3,
        max_retries: ty.Optional[int] = None,
    ) -> _T:
        connection_name = type(self).__name__
        attempts = 0
        while True:
            try:
                result = await func()
                self._ctx.model.runtime_status.mark_connection_successful(
                    connection_name
                )
                self._ctx.model.notify_update()
                return result
            except Exception as ex:
                is_temporary = api.is_temporary_error(ex)
                await logger.awarning(
                    "Error from API",
                    is_temporary=is_temporary,
                    description=description,
                    exc_info=ex,
                )

                if is_temporary:
                    self._ctx.model.runtime_status.mark_connection_failure(
                        connection_name
                    )
                    self._ctx.model.notify_update()
                    attempts += 1
                    if max_retries is not None and attempts >= max_retries:
                        raise
                    await anyio.sleep(retry_delay)
                else:
                    raise


class ForegroundTask:
    """
    A short-lived task that executes in foreground (while wait box is shown).
    """

    def run(self, task_context: TaskContext, wait_box: WaitBox) -> None:
        self._ctx = task_context
        self._wait_box = wait_box
        with structlog.contextvars.bound_contextvars(
            foreground_task=type(self).__name__
        ):
            return self._run()

    def merge_from(self, other: tye.Self) -> None:
        pass

    @abstractmethod
    def _run(self) -> None: ...
