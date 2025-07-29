"""
Defines the current state of the extension.

All tasks store their state and communicate with others via the `Model` object.
"""

import time
import typing as ty
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field

import anyio
import typing_extensions as tye
from pydantic import BaseModel

from decompai_client import (
    Function,
    FunctionOverview,
    Name,
    ParametersMapping,
    Thunk,
    UserConfig,
    VariablesMapping,
    GlobalVariable,
)
from decompai_ida import ida_tasks, storage
from decompai_ida.ida_tasks import AsyncCallback
from decompai_ida.serialization import EncodedBytes

if ty.TYPE_CHECKING:
    from decompai_ida.tasks import ForegroundTask
    from decompai_ida.ui.copilot import Message


# Similar to definitions of `Object` and `Inference` from API, but easier to
# work with since they exclude `None`.

Object: tye.TypeAlias = ty.Union[Function, Thunk, GlobalVariable]

Inference: tye.TypeAlias = ty.Union[
    FunctionOverview, Name, ParametersMapping, VariablesMapping
]


class SyncStatus(BaseModel, frozen=True):
    """
    Attached to every address of object we sync with the server.
    """

    uploaded_hash: ty.Optional[EncodedBytes] = None
    """
    Hash of the uploaded object. `None` means not uploaded.
    """

    dirty: bool = True
    """
    True if object is suspected to have been changed.
    """

    def with_dirty(self, dirty: bool) -> "SyncStatus":
        return SyncStatus(uploaded_hash=self.uploaded_hash, dirty=dirty)


class Revision(BaseModel, frozen=True):
    """
    Revision to be uploaded.
    """

    objects: tuple[Object, ...]
    is_initial_analysis: bool


TaskName = ty.Literal[
    "uploading", "downloading", "waiting_for_ida", "registering"
]


@dataclass(frozen=True)
class RemoteAnalysisStats:
    start_time: float
    start_revision: float


@dataclass
class RuntimeStatus:
    """
    Current runtime (non-persistent) state.
    """

    user_config: ty.Optional[UserConfig] = None
    active_tasks: set[TaskName] = field(default_factory=set)
    apply_inferences_when_ready: bool = False
    connection_failures: dict[str, float] = field(default_factory=dict)
    initial_analysis_complete = False
    foreground_task_queue: deque[type["ForegroundTask"]] = field(
        default_factory=deque
    )
    foreground_task_active: bool = False
    ida_settled: bool = False
    """
    Whether IDA stopped doing modifications to the database.
    """

    disabled: bool = False
    "Whether plugin is currently disabled"

    remote_analysis_stats: ty.Optional[RemoteAnalysisStats] = None

    def mark_connection_successful(self, name: str):
        if name in self.connection_failures:
            del self.connection_failures[name]

    def mark_connection_failure(self, name: str):
        if name not in self.connection_failures:
            self.connection_failures[name] = time.monotonic()

    def queue_foreground_task_if_not_already_queued(
        self, new_task_type: type["ForegroundTask"]
    ):
        # Note - if tasks become parameterized, this should probably replace
        # existing task.
        if new_task_type not in self.foreground_task_queue:
            self.foreground_task_queue.append(new_task_type)


@dataclass
class CopilotModel:
    """
    Model for copilot chat state and communication.
    """

    messages: list["Message"] = field(default_factory=list)
    is_active: bool = False
    stop_requested: bool = False
    clear_requested: bool = False
    mcp_server_port: ty.Optional[int] = None
    _updated: anyio.Event = field(init=False)
    notify_update: AsyncCallback = field(init=False)

    def __post_init__(self):
        self.notify_update = AsyncCallback(self._notify_update)
        self._updated = anyio.Event()

    async def wait_for_update(self):
        """
        Wait for update notification (via `notify_update`).
        """
        await self._updated.wait()

    def _notify_update(self):
        """
        Wake all tasks waiting for update.
        """
        self._updated.set()
        self._updated = anyio.Event()


class Model:
    """
    All extension state.
    """

    @staticmethod
    async def create():
        instance = Model()
        await ida_tasks.run(instance._open_storages_sync)
        return instance

    def __init__(self):
        "Use `create` instead"
        self.notify_update = AsyncCallback(self._notify_update)
        self.runtime_status = RuntimeStatus()
        self._updated = anyio.Event()
        self.copilot_model = CopilotModel()

    def _open_storages_sync(self):
        "Use `create`!"
        self.binary_id = storage.SingleValue(
            "binary_id", ty.Optional[str], default=None
        )
        self.initial_upload_complete = storage.SingleValue(
            "initial_upload_complete", bool, default=False
        )
        self.initial_upload_suggested = storage.SingleValue(
            "initial_upload_suggested", bool, default=False
        )
        self.original_files_uploaded = storage.SingleValue(
            "original_files_uploaded", bool, default=False
        )
        self.database_dirty = storage.SingleValue(
            "database_dirty", bool, default=True
        )
        self.revision = storage.SingleValue("revision", int, default=0)
        self.inference_cursor: storage.SingleValue[ty.Optional[int]] = (
            storage.SingleValue(
                "inference_cursor", ty.Optional[int], default=None
            )
        )
        self.server_revision = storage.SingleValue(
            "server_revision", float, default=0.0
        )
        self.last_done_revision = storage.SingleValue(
            "last_done_revision", float, default=0.0
        )
        self.sync_status = storage.AddressMap("sync_status", SyncStatus)
        self.inferences = storage.AddressMultiMap("inferences", Inference)
        self.pending_inferences = storage.AddressMultiMap(
            "pending_inferences", Inference
        )
        self.revision_queue = storage.Queue("revision_queue", Revision)
        self.inference_queue = storage.Queue("inference_queue", Inference)
        self.tid_to_object = storage.AddressRelation("tid_to_object")

    def _notify_update(self) -> None:
        """
        Wake all tasks waiting for update.
        """
        self._updated.set()
        self._updated = anyio.Event()

    async def wait_for_update(self):
        """
        Wait for update notification (via `notify_update`).
        """
        await self._updated.wait()

    @contextmanager
    def report_and_notify_background_task(self, background_task: TaskName):
        self.runtime_status.active_tasks.add(background_task)
        self.notify_update()
        try:
            yield
        finally:
            self.runtime_status.active_tasks.remove(background_task)
            self.notify_update()

    async def wait_for_initial_analysis(self):
        while not self.runtime_status.initial_analysis_complete:
            await self.wait_for_update()

    async def wait_for_registration(self):
        while (await self.binary_id.get()) is None:
            await self.wait_for_update()

    async def wait_for_user_config(self) -> UserConfig:
        while self.runtime_status.user_config is None:
            await self.wait_for_update()
        return self.runtime_status.user_config
