import time
import typing as ty

import anyio
import ida_idp
import ida_kernwin
from decompai_ida.copilot_task import CopilotTask
import exceptiongroup

from decompai_client import BinariesApi, UserApi
from decompai_client.exceptions import ForbiddenException, UnauthorizedException
from decompai_ida import (
    api,
    binary,
    configuration,
    ida_tasks,
    logger,
    messages,
)
from decompai_ida.apply_pending_inferences_task import (
    ApplyPendingInferencesTask,
)
from decompai_ida.async_utils import wait_for_object_of_type
from decompai_ida.broadcast import Broadcast
from decompai_ida.broadcast_ida_events_task import (
    BroadcastHexRaysEventsTask,
    BroadcastIdaEventsTask,
)
from decompai_ida.download_inferences_task import DownloadInferencesTask
from decompai_ida.events import DatabaseOpened, EventRecorder, IdaEvent
from decompai_ida.fetch_user_config_task import FetchUserConfigTask
from decompai_ida.ask_initial_questions_task import AskInitialQuestions
from decompai_ida.model import CopilotModel, Model
from decompai_ida.monitor_initial_analysis_task import (
    MonitorInitialAnalysisTask,
)
from decompai_ida.poll_server_status_task import PollServerStatusTask
from decompai_ida.register_binary_task import (
    BinaryExceedsSizeLimitError,
    RegisterBinaryTask,
)
from decompai_ida.show_initial_upload_message_task import (
    ShowInitialUploadMessageTask,
)
from decompai_ida.start_foreground_tasks_task import StartForegroundTasksTask
from decompai_ida.tasks import (
    GlobalTask,
    GlobalTaskContext,
    StaticConfiguration,
    Task,
    TaskContext,
)
from decompai_ida.track_changes_task import TrackChangesTask
from decompai_ida.track_ida_settled_task import TrackIdaSettledTask
from decompai_ida.trigger_apply_inferences_task import (
    TriggerApplyInferencesTask,
)
from decompai_ida.upload_original_files_task import UploadOriginalFilesTask
from decompai_ida.upload_sections_task import UploadSectionsTask
from decompai_ida.upload_revisions_task import UploadRevisionsTask

try:
    from decompai_ida.ui.ui_task import UiTask
    from decompai_ida.ui.copilot_ui_task import CopilotUiTask
    from decompai_ida.ui.swift_ui_task import SwiftUiTask
    from decompai_ida.ui.functions_colorizer_task import FunctionsColorizerTask
    from decompai_ida.ui.zenyard_menu_task import ZenyardMenuTask

    _UI_GLOBAL_TASKS = [
        ZenyardMenuTask,
    ]

    _UI_TASKS = [
        CopilotUiTask,
        FunctionsColorizerTask,
        SwiftUiTask,
        UiTask,
    ]
except Exception:
    _UI_GLOBAL_TASKS = []
    _UI_TASKS = []

_STATIC_CONFIG = StaticConfiguration(
    max_objects_in_revision=64,
    max_upload_bytes=2 * 1024 * 1024,
)

# Tasks that run without any database open.
_GLOBAL_TASKS: ty.Collection[type[GlobalTask]] = (
    BroadcastIdaEventsTask,
    *_UI_GLOBAL_TASKS,
)

# Tasks that run when a DB is open (inactive or active).
_TASKS: ty.Collection[type[Task]] = (
    ApplyPendingInferencesTask,
    BroadcastHexRaysEventsTask,
    CopilotTask,
    FetchUserConfigTask,
    TrackChangesTask,
    TrackIdaSettledTask,
    *_UI_TASKS,
    # TODO: Restore MaintainTidToObjectTask once we resolve crashes
)

# Tasks that run when a DB is open and plugin is active.
_ACTIVE_TASKS: ty.Collection[type[Task]] = (
    DownloadInferencesTask,
    MonitorInitialAnalysisTask,
    PollServerStatusTask,
    AskInitialQuestions,
    RegisterBinaryTask,
    ShowInitialUploadMessageTask,
    StartForegroundTasksTask,
    TriggerApplyInferencesTask,
    UploadOriginalFilesTask,
    UploadSectionsTask,
    UploadRevisionsTask,
)

_stop: ty.Optional[ty.Callable[[bool], None]] = None
_stop_db_tasks: ty.Optional[ty.Callable[[], None]] = None


def stop(*, restart=False, wait=False):
    "Stop the plugin for this IDA session"

    stop_callback = _stop
    if stop_callback is None:
        return

    stop_callback(restart)

    if not restart and wait:
        while _stop is not None:
            ida_tasks.execute_queued_tasks_sync()
            time.sleep(0.05)
        ida_tasks.execute_queued_tasks_sync()


def stop_db_tasks():
    stop_callback = _stop_db_tasks
    if stop_callback is None:
        return

    stop_callback()
    while _stop_db_tasks is not None:
        ida_tasks.execute_queued_tasks_sync()
        time.sleep(0.05)
    ida_tasks.execute_queued_tasks_sync()


class _StopDbTasksOnHexraysUnload(ida_kernwin.UI_Hooks):
    # Comparing with the UI label of the plugin. Note that non-UI identifiers
    # changes between architectures (e.g. `hexx64` and `hexarm`).
    _HEXRAYS_ORG_NAMES = {"Hex-Rays Decompiler", "Hex-Rays Cloud Decompiler"}

    def plugin_unloading(self, plugin_info):
        if plugin_info.org_name in self._HEXRAYS_ORG_NAMES:
            logger.info(
                "Stopping DB tasks because HexRays plugin unloaded",
                plugin_id=plugin_info.idaplg_name,
                plugin_label=plugin_info.org_name,
            )
            stop_db_tasks()

            # HexRays hooks must be removed before continuing to avoid crash.
            ida_tasks.unhook_all_hexrays_sync()

        return super().plugin_unloading(plugin_info)


class _StopDbTasksOnCloseHook(ida_idp.IDB_Hooks):
    def closebase(self, /):
        stop_db_tasks()
        return super().closebase()


async def main():
    # Warning - don't add any awaits before assigning `_stop` to allow early
    # cancellation.

    global _stop
    ida_tasks.AsyncCallback.set_event_loop()
    should_restart = True

    while should_restart:
        should_restart = False
        try:
            async with (
                # Open TaskGroup first to wrap all exceptions with ExceptiopGroup
                anyio.create_task_group() as tg,
            ):

                def stop(restart: bool):
                    nonlocal should_restart
                    should_restart = restart
                    tg.cancel_scope.cancel()

                _stop = ida_tasks.AsyncCallback(stop)

                async with api.open_api_client() as api_client:
                    ida_events = Broadcast[IdaEvent](EventRecorder())
                    global_context = GlobalTaskContext(
                        ida_events=ida_events,
                        static_config=_STATIC_CONFIG,
                        api_client=api_client,
                    )

                    for global_task_type in _GLOBAL_TASKS:
                        tg.start_soon(global_task_type(global_context).run)

                    await _spawn_tasks_when_db_opens(global_context)

        except exceptiongroup.ExceptionGroup as ex:
            config_path = await ida_tasks.run(
                configuration.get_config_path_sync
            )

            if ex.subgroup(configuration.BadConfigurationFile):
                await messages.warn_bad_configuration(config_path=config_path)
            else:
                exceptiongroup.print_exception(ex)

        finally:
            _stop = None


async def _spawn_tasks_when_db_opens(global_context: GlobalTaskContext):
    global _stop_db_tasks

    async with global_context.ida_events.subscribe() as event_receiver:
        while True:
            await wait_for_object_of_type(event_receiver, DatabaseOpened)

            try:
                async with anyio.create_task_group() as tg:
                    _stop_db_tasks = ida_tasks.AsyncCallback(
                        tg.cancel_scope.cancel
                    )
                    async with (
                        ida_tasks.install_hooks(_StopDbTasksOnCloseHook()),
                        ida_tasks.install_hooks(_StopDbTasksOnHexraysUnload()),
                    ):
                        await _spawn_tasks(global_context)
            finally:
                _stop_db_tasks = None


async def _spawn_tasks(global_context: GlobalTaskContext):
    # Save model to global, to allow interactive access.
    global model

    idb_path = await ida_tasks.run(binary.get_idb_path_sync)
    log_path = idb_path.with_suffix(".log")

    model = await Model.create()

    plugin_config = await ida_tasks.run(configuration.read_configuration_sync)

    task_context = TaskContext(
        model=model,
        copilot_model=CopilotModel(),
        ida_events=global_context.ida_events,
        binaries_api=BinariesApi(global_context.api_client),
        user_api=UserApi(global_context.api_client),
        plugin_config=plugin_config,
        static_config=global_context.static_config,
    )

    with logger.open(log_path, plugin_config.log_level):
        async with anyio.create_task_group() as tg:
            for task_type in _TASKS:
                tg.start_soon(
                    task_type(task_context).run, name=task_type.__name__
                )

            try:
                await _spawn_active_tasks(task_context)
            except exceptiongroup.ExceptionGroup as ex:
                handled, rest = ex.split(
                    (
                        ForbiddenException,
                        UnauthorizedException,
                        BinaryExceedsSizeLimitError,
                    )
                )

                if handled is not None:
                    if _extract_exception(handled, ForbiddenException):
                        await messages.warn_no_permission_for_binary()
                    if _extract_exception(handled, UnauthorizedException):
                        await messages.warn_bad_credentials_message()
                    if size_error := _extract_exception(
                        handled, BinaryExceedsSizeLimitError
                    ):
                        await messages.warn_binary_exceeds_max_size(
                            max_size_mb=size_error.max_binary_size_mb
                        )

                if rest is not None:
                    raise rest

                # Just continue in disabled state.
                model.runtime_status.disabled = True
                model.notify_update()


async def _spawn_active_tasks(task_context: TaskContext):
    async with anyio.create_task_group() as tg:
        for task_type in _ACTIVE_TASKS:
            tg.start_soon(task_type(task_context).run, name=task_type.__name__)


_E = ty.TypeVar("_E", bound=Exception)


def _extract_exception(
    group: exceptiongroup.ExceptionGroup, ex_type: type[_E]
) -> ty.Optional[_E]:
    subgroup = group.subgroup(ex_type)
    if subgroup is None:
        return

    for item in subgroup.exceptions:
        if isinstance(item, exceptiongroup.ExceptionGroup):
            extracted = _extract_exception(item, ex_type)
            if extracted is not None:
                return extracted
        else:
            return item
