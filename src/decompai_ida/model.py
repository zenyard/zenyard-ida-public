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
    BinaryStatePaused,
    Function,
    FunctionOverview,
    GlobalVariable,
    Name,
    NotSwift,
    ParametersMapping,
    ParameterType,
    ReturnType,
    StructDefinition,
    SwiftFunction,
    Thunk,
    UserConfig,
    VariablesMapping,
)
from decompai_client.models.unlimited_usage import UnlimitedUsage
from decompai_client.models.limited_usage import LimitedUsage
from decompai_client.models.expired_usage import ExpiredUsage
from decompai_client.models.binary_state import BinaryState

from decompai_ida import ida_tasks, storage
from decompai_ida.ida_tasks import AsyncCallback
from decompai_ida.serialization import EncodedBytes

if ty.TYPE_CHECKING:
    from decompai_ida.tasks import ForegroundTask


# Similar to definitions of `Object` and `Inference` from API, but easier to
# work with since they exclude `None`.

Object: tye.TypeAlias = ty.Union[Function, Thunk, GlobalVariable]

AddressInference: tye.TypeAlias = ty.Union[
    FunctionOverview,
    Name,
    ParametersMapping,
    VariablesMapping,
    SwiftFunction,
    ParameterType,
    ReturnType,
    NotSwift,
]
GlobalInference: tye.TypeAlias = StructDefinition
Inference: tye.TypeAlias = ty.Union[AddressInference, GlobalInference]


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


class AddressUserOptions(BaseModel, frozen=True):
    analyze_as_swift: ty.Optional[bool] = None

    def with_analyze_as_swift(
        self, analyze_as_swift: bool
    ) -> "AddressUserOptions":
        return AddressUserOptions(analyze_as_swift=analyze_as_swift)


class Revision(BaseModel, frozen=True):
    """
    Revision to be uploaded.
    """

    objects: tuple[Object, ...]
    is_initial_analysis: bool
    swift_only: bool = False
    perform_global_analysis: bool = False


TaskName = ty.Literal[
    "uploading", "downloading", "waiting_for_ida", "registering"
]


@dataclass
class RuntimeStatus:
    """
    Current runtime (non-persistent) state.
    """

    user_config: ty.Optional[UserConfig] = None
    user_plans_usage: ty.Union[
        ExpiredUsage, LimitedUsage, UnlimitedUsage, None
    ] = None
    active_tasks: set[TaskName] = field(default_factory=set)
    apply_inferences_when_ready: bool = False
    connection_failures: dict[str, float] = field(default_factory=dict)
    initial_analysis_complete = False
    foreground_task_queue: deque["ForegroundTask"] = field(
        default_factory=deque
    )
    foreground_task_active: bool = False
    ida_settled: bool = False
    """
    Whether IDA stopped doing modifications to the database.
    """

    disabled: bool = False
    "Whether plugin is currently disabled"

    binary_state: ty.Optional[BinaryState] = None

    def mark_connection_successful(self, name: str):
        if name in self.connection_failures:
            del self.connection_failures[name]

    def mark_connection_failure(self, name: str):
        if name not in self.connection_failures:
            self.connection_failures[name] = time.monotonic()

    def queue_foreground_task_if_not_already_queued(
        self, new_task: "ForegroundTask"
    ):
        for existing in self.foreground_task_queue:
            if type(existing) is type(new_task):
                existing.merge_from(new_task)
                return
        self.foreground_task_queue.append(new_task)


@dataclass
class Message:
    sender: ty.Literal["AI", "User"]
    text: str
    tool_count: ty.Optional[int] = None


@dataclass(frozen=True)
class Task:
    content: str
    status: ty.Literal["pending", "in_progress", "completed"]


@dataclass
class CopilotModel:
    """
    Model for copilot chat state and communication.
    """

    messages: list["Message"] = field(default_factory=list)
    tasks: list[Task] = field(default_factory=list)
    is_active: bool = False
    stop_requested: bool = False
    clear_requested: bool = False
    notify_update: AsyncCallback = field(init=False)
    _updated: anyio.Event = field(init=False)

    def __post_init__(self):
        """
        Initialize event loop objects.

        Note: This should only be called via create() from async context.
        Direct instantiation outside async context will cause GC issues on macOS.
        """
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


def is_usage_exhausted(
    usage: ty.Union[ExpiredUsage, LimitedUsage, UnlimitedUsage, None],
) -> bool:
    if isinstance(usage, ExpiredUsage):
        return True
    if isinstance(usage, LimitedUsage) and float(usage.usage_percentage) >= 1.0:
        return True
    return False


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
        self.swift_source_available = False

    def _open_storages_sync(self):
        "Use `create`!"
        self.binary_id = storage.SingleValue(
            "binary_id", ty.Optional[str], default=None
        )
        self.initial_upload_complete = storage.SingleValue(
            "initial_upload_complete", bool, default=False
        )
        # NOTE: Storage name keeps historical "initial_upload_suggested" key for
        # backward compatibility while the model field is renamed.
        self.asked_initial_questions = storage.SingleValue(
            "initial_upload_suggested", bool, default=False
        )
        self.ready_for_analysis = storage.SingleValue(
            "ready_for_analysis", bool, default=False
        )
        self.binary_instructions = storage.SingleValue(
            "binary_instructions", ty.Optional[str], default=None
        )
        self.original_files_uploaded = storage.SingleValue(
            "original_files_uploaded", bool, default=False
        )
        self.sections_uploaded = storage.SingleValue(
            "sections_uploaded", bool, default=False
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
        self.inferences = storage.AddressMultiMap(
            "inferences", AddressInference
        )
        self.pending_inferences = storage.AddressMultiMap(
            "pending_inferences", AddressInference
        )
        self.revision_queue = storage.Queue("revision_queue", Revision)
        self.inference_queue = storage.Queue("inference_queue", Inference)
        self.tid_to_object = storage.AddressRelation("tid_to_object")
        self.sections_excluded_from_upload = storage.AddressMap(
            "sections_excluded_from_upload", bool
        )
        self.address_user_options = storage.AddressMap(
            "address_user_options", AddressUserOptions
        )
        self.paused_dialog_shown = storage.SingleValue(
            "paused_dialog_shown", bool, default=False
        )
        self.pending_inference_counts = storage.SingleValue(
            "pending_inference_counts", dict[str, int], default={}
        )
        self.copilot_session_notes = storage.SingleValue(
            "copilot_session_notes", ty.Optional[str], default=None
        )

        # Type management storage
        # Maps struct_id -> StructDefinition
        self.struct_definitions = storage.StrMap(
            "struct_definitions", StructDefinition
        )
        # Maps struct_id -> list of struct_ids it depends on
        self.struct_dependencies = storage.StrMap(
            "struct_dependencies", list[str]
        )
        # Per-function struct usage: maps address -> {param_index: struct_id, "return": struct_id}
        # Keys are stringified param indices ("0", "1", etc.) or "return"
        self.function_struct_usage = storage.AddressMap(
            "function_struct_usage", dict[str, str]
        )
        # Maps struct_id -> effective_name used when registering in IDA
        # Used to know what name to delete when removing a struct
        self.registered_struct_names = storage.StrMap(
            "registered_struct_names", str
        )
        # Original type annotations for applying/re-applying when structs become
        # available or get renamed due to collisions.
        # Maps address -> {param_index_or_return: original_type_annotation}
        self.function_original_type_annotations = storage.AddressMap(
            "function_original_type_annotations", dict[str, str]
        )

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

    async def wait_for_initial_questions(self):
        while not await self.asked_initial_questions.get():
            await self.wait_for_update()

    async def wait_for_ready_for_analysis(self):
        while not await self.ready_for_analysis.get():
            await self.wait_for_update()

    async def wait_for_user_config(self) -> UserConfig:
        while self.runtime_status.user_config is None:
            await self.wait_for_update()
        return self.runtime_status.user_config

    async def wait_for_paused_state(self) -> bool:
        while self.is_considered_paused is None:
            await self.wait_for_update()

        return self.is_considered_paused

    @property
    def is_considered_paused(self) -> ty.Optional[bool]:
        """
        True - definitely psued
        False - definitely unpaused
        None - not known yet
        """

        # Use explicit state if known
        if (
            self.runtime_status.binary_state is not None
            and self.runtime_status.binary_state.actual_instance is not None
        ):
            return isinstance(
                self.runtime_status.binary_state.actual_instance,
                BinaryStatePaused,
            )

        # Fall back to assuming state from plan status
        if self.runtime_status.user_plans_usage is not None:
            return is_usage_exhausted(self.runtime_status.user_plans_usage)

        # Not enough information yet
        return None

    def push_inference_sync(self, inference: Inference) -> None:
        self.inference_queue.push_sync(inference)
        counts = self.pending_inference_counts.get_sync()
        type_name = type(inference).__name__
        counts[type_name] = counts.get(type_name, 0) + 1
        self.pending_inference_counts.set_sync(counts)

    async def push_inference(self, inference: Inference) -> None:
        await ida_tasks.run(self.push_inference_sync, inference)

    def pop_inferences_sync(self, count: int) -> None:
        batch = self.inference_queue.peek_sync(count)
        self.inference_queue.pop_sync(count)
        counts = self.pending_inference_counts.get_sync()
        for inference in batch:
            if inference is not None:
                type_name = type(inference).__name__
                c = counts.get(type_name, 0) - 1
                if c <= 0:
                    counts.pop(type_name, None)
                else:
                    counts[type_name] = c
        self.pending_inference_counts.set_sync(counts)

    async def clear_all(self):
        await self.binary_id.clear()
        await self.initial_upload_complete.clear()
        await self.asked_initial_questions.clear()
        await self.ready_for_analysis.clear()
        await self.binary_instructions.clear()
        await self.original_files_uploaded.clear()
        await self.sections_uploaded.clear()
        await self.database_dirty.clear()
        await self.revision.clear()
        await self.inference_cursor.clear()
        await self.server_revision.clear()
        await self.last_done_revision.clear()
        await self.sync_status.clear()
        await self.inferences.clear()
        await self.pending_inferences.clear()
        await self.revision_queue.clear()
        await self.inference_queue.clear()
        await self.tid_to_object.clear()
        await self.sections_excluded_from_upload.clear()
        await self.address_user_options.clear()
        await self.paused_dialog_shown.clear()
        await self.struct_definitions.clear()
        await self.struct_dependencies.clear()
        await self.function_struct_usage.clear()
        await self.registered_struct_names.clear()
        await self.function_original_type_annotations.clear()
        await self.pending_inference_counts.set({})
        await self.copilot_session_notes.clear()
