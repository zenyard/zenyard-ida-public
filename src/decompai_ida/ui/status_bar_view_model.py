from dataclasses import dataclass
import math
import time
import typing as ty

from PyQt5.QtCore import QObject, pyqtSignal

from decompai_ida import ida_tasks
from decompai_ida.model import Model, TaskName

# Time, in seconds, between disconnection warning being set until it is
# actually reported to user.
_DISCONNECTION_GRACE_PERIOD = 60

# Time to wait before showing ETA, to let it stabilize.
_ETA_CALCULATION_TIME = 30


class StatusBarViewModel(QObject):
    """
    Supplies UI with details from model.
    """

    status_line = pyqtSignal(str)
    results_available = pyqtSignal(bool)
    upload_available = pyqtSignal(bool)
    disconnected_icon_visible = pyqtSignal(bool)
    progress_bar_visible = pyqtSignal(bool)
    progress_bar_range = pyqtSignal(int, int)
    progress_bar_value = pyqtSignal(int)
    swift_source_available_icon_visible = pyqtSignal(bool)

    def __init__(self, model: Model):
        super().__init__()
        self._model = model

    async def emit_current_state(self):
        await self._emit_activity_details()
        self._emit_connectivity_warning()
        self._emit_swift_source_available()

    async def _emit_activity_details(self):
        if self._model.runtime_status.disabled:
            self._emit_status("Disabled")

        elif self._is_background_task_active("waiting_for_ida"):
            self._emit_status("Waiting for IDA", progress="busy")

        elif (
            self._model.runtime_status.foreground_task_active
            or len(self._model.runtime_status.foreground_task_queue) > 0
        ):
            self._emit_status("Working")

        elif self._is_background_task_active("registering"):
            self._emit_status("Registering at server", progress="busy")

        elif (
            analysis_status := await ida_tasks.run(
                self._get_analysis_status_sync
            )
        ) is not None:
            if analysis_status.eta is not None:
                formatted_eta = _format_eta(analysis_status.eta)
                eta_label = f"{formatted_eta} left"
            else:
                eta_label = "calculating ETA..."

            self._emit_status(
                f"Analyzing in background - {eta_label}",
                progress=analysis_status.progress,
            )

        elif self._is_background_task_active("uploading"):
            self._emit_status("Uploading data", progress="busy")

        elif self._is_background_task_active("downloading"):
            self._emit_status("Downloading results", progress="busy")

        elif await self._model.inference_queue.size() > 0:
            self._emit_status(
                "New results ready — Click to apply", icon="results_available"
            )

        elif await self._model.database_dirty.get():
            self._emit_status(
                (
                    "Click to analyze with Zenyard"
                    if not await self._model.initial_upload_complete.get()
                    else "Updates detected — Click to analyze"
                ),
                icon="upload_available",
            )

        else:
            self._emit_status("Latest results applied")

    def _emit_connectivity_warning(self):
        if len(self._model.runtime_status.connection_failures) == 0:
            self.disconnected_icon_visible.emit(False)
            return

        earliest_connection_failure = min(
            self._model.runtime_status.connection_failures.values()
        )
        disconnection_time = time.monotonic() - earliest_connection_failure
        self.disconnected_icon_visible.emit(
            disconnection_time > _DISCONNECTION_GRACE_PERIOD
        )

    def _emit_swift_source_available(self):
        self.swift_source_available_icon_visible.emit(
            self._model.swift_source_available
        )

    def _emit_status(
        self,
        label,
        *,
        progress: ty.Union[ty.Literal["busy"], float, None] = None,
        icon: ty.Optional[
            ty.Literal["upload_available", "results_available"]
        ] = None,
    ):
        self.status_line.emit(label)
        self._emit_progress(progress)
        self.upload_available.emit(icon == "upload_available")
        self.results_available.emit(icon == "results_available")

    def _emit_progress(self, value: ty.Union[ty.Literal["busy"], float, None]):
        if value == "busy":
            self.progress_bar_visible.emit(True)
            self.progress_bar_range.emit(0, 0)
            self.progress_bar_value.emit(0)

        elif isinstance(value, float):
            self.progress_bar_visible.emit(True)
            self.progress_bar_range.emit(0, 100)
            self.progress_bar_value.emit(int(value * 100))

        else:
            self.progress_bar_visible.emit(False)

    def _is_background_task_active(self, task_name: TaskName) -> bool:
        return task_name in self._model.runtime_status.active_tasks

    def _get_analysis_status_sync(self) -> ty.Optional["_AnalysisStatus"]:
        uploaded_revision = self._model.revision.get_sync()
        server_revision = self._model.server_revision.get_sync()

        if uploaded_revision == server_revision:
            # No revision was uploaded yet. We prefer showing "Uploading" over
            # "Analyzing" in this state.
            return

        revisions_in_upload_queue = self._model.revision_queue.size_sync()
        revision = uploaded_revision + revisions_in_upload_queue
        last_done_revision = self._model.last_done_revision.get_sync()

        # Avoid division by zero
        if revision == last_done_revision:
            return

        progress = (server_revision - last_done_revision) / (
            revision - last_done_revision
        )

        eta = self._calculate_eta(
            revision=revision, server_revision=server_revision
        )

        return _AnalysisStatus(progress=progress, eta=eta)

    def _calculate_eta(
        self, *, revision: int, server_revision: float
    ) -> ty.Optional[float]:
        stats = self._model.runtime_status.remote_analysis_stats
        if stats is None:
            return

        if stats.start_revision == server_revision:
            # No progress yet
            return

        time_since_stats = time.monotonic() - stats.start_time
        if time_since_stats < _ETA_CALCULATION_TIME:
            return

        progress_since_stats = (server_revision - stats.start_revision) / (
            revision - stats.start_revision
        )

        distance = 1 - progress_since_stats
        speed = progress_since_stats / time_since_stats
        return distance / speed


@dataclass(frozen=True)
class _AnalysisStatus:
    progress: float
    eta: ty.Optional[float]


def _format_eta(seconds: float) -> str:
    minutes = math.ceil(seconds / 60)
    hours, minutes_left = divmod(minutes, 60)
    if hours:
        return f"{hours}h{f' {minutes_left}m' if minutes_left else ''}"
    return f"{minutes_left}m"
