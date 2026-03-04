from dataclasses import dataclass
from decimal import Decimal
import math
import time
import typing as ty

from qtpy.QtCore import QObject, Signal

from decompai_client.models.expired_usage import ExpiredUsage
from decompai_client.models.limited_usage import LimitedUsage
from decompai_client.models.unlimited_usage import UnlimitedUsage
from decompai_client.models.binary_state_queued import BinaryStateQueued

from decompai_ida import ida_tasks
from decompai_ida.model import Model, TaskName
from decompai_ida.ui._status_bar_format import (
    PendingInferenceCounts,
    _format_compact_count,
)

# Time, in seconds, between disconnection warning being set until it is
# actually reported to user.
_DISCONNECTION_GRACE_PERIOD = 60

_USAGE_PERCENT_FULL = Decimal(1.0)
_USAGE_PERCENT_NEAR_END = Decimal(0.8)


@dataclass
class UsageState:
    text: str
    tooltip: str
    clickable: bool
    status: str


class StatusBarViewModel(QObject):
    """
    Supplies UI with details from model.
    """

    status_line = Signal(str)
    results_available = Signal(bool)
    results_tooltip = Signal(str)
    upload_available = Signal(bool)
    disconnected_icon_visible = Signal(bool)
    progress_bar_visible = Signal(bool)
    progress_bar_range = Signal(int, int)
    progress_bar_value = Signal(int)
    swift_source_available_icon_visible = Signal(bool)
    usage_text = Signal(str)
    usage_visible = Signal(bool)
    usage_status = Signal(str)
    usage_tooltip = Signal(str)
    usage_clickable = Signal(bool)

    def __init__(self, model: Model):
        super().__init__()
        self._model = model

    async def emit_current_state(self):
        await self._emit_activity_details()
        self._emit_connectivity_warning()
        self._emit_swift_source_available()
        self._emit_usage()

    async def _emit_activity_details(self):
        raw_counts = await self._model.pending_inference_counts.get()
        counts = PendingInferenceCounts.from_raw_counts(raw_counts)
        ready_count = counts.total
        self.results_tooltip.emit(counts.format_tooltip())

        if self._model.runtime_status.disabled:
            self._emit_status("Disabled")

        elif self._model.is_considered_paused:
            self._emit_status("Quota reached")

        elif self._is_background_task_active("waiting_for_ida"):
            self._emit_status(
                self._with_results_ready("Waiting for IDA", ready_count),
                progress="busy",
            )

        elif (
            self._model.runtime_status.foreground_task_active
            or len(self._model.runtime_status.foreground_task_queue) > 0
        ):
            self._emit_status(self._with_results_ready("Working", ready_count))

        elif self._is_background_task_active("registering"):
            self._emit_status(
                self._with_results_ready("Registering at server", ready_count),
                progress="busy",
            )

        elif (queue_position := self._get_queue_position()) is not None:
            self._emit_status(
                f"In queue ({queue_position} remaining)", progress="busy"
            )

        elif (
            analysis_progress := await ida_tasks.run(
                self._get_analysis_progress_sync
            )
        ) is not None:
            self._emit_status(
                self._with_results_ready(
                    "Analyzing in background", ready_count
                ),
                progress=analysis_progress,
            )

        elif self._is_background_task_active("uploading"):
            self._emit_status(
                self._with_results_ready("Uploading data", ready_count),
                progress="busy",
            )

        elif self._is_background_task_active("downloading"):
            self._emit_status(
                self._with_results_ready("Downloading results", ready_count),
                progress="busy",
            )

        elif ready_count > 0:
            self._emit_status(
                f"{_format_compact_count(ready_count)} results ready — Click to apply",
                icon="results_available",
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

    def _emit_usage(self):
        """Emit usage text for display in status bar."""
        usage = self._model.runtime_status.user_plans_usage

        if not usage or isinstance(usage, UnlimitedUsage):
            self.usage_visible.emit(False)
            self.usage_clickable.emit(False)
            return

        usage_state = self._get_usage_state(usage)
        self.usage_status.emit(usage_state.status)
        self.usage_text.emit(usage_state.text)
        self.usage_tooltip.emit(usage_state.tooltip)
        self.usage_visible.emit(True)
        self.usage_clickable.emit(usage_state.clickable)

    def _get_usage_state(
        self, usage: ExpiredUsage | LimitedUsage | UnlimitedUsage | None
    ) -> UsageState:
        match usage:
            case ExpiredUsage():
                return UsageState(
                    text="EXPIRED",
                    tooltip="Your Zenyard plan has ended. Contact us to continue.",
                    clickable=True,
                    status="critical",
                )

            case LimitedUsage(usage_percentage=pct) if (
                pct >= _USAGE_PERCENT_FULL
            ):
                return UsageState(
                    text="Usage: 100%",
                    tooltip="You’ve used all of your Zenyard quota for your current plan.",
                    clickable=True,
                    status="critical",
                )
            case LimitedUsage(usage_percentage=pct) if (
                pct >= _USAGE_PERCENT_NEAR_END
            ):
                safe_pct = math.floor(pct * 1000) / 10
                return UsageState(
                    text=f"Usage: {safe_pct:.1f}%",
                    tooltip="Your Zenyard quota is reaching its limit.",
                    clickable=False,
                    status="warning",
                )
            case LimitedUsage(usage_percentage=pct):
                safe_pct = math.floor(pct * 1000) / 10
                return UsageState(
                    text=f"Usage: {safe_pct:.1f}%",
                    tooltip="Percent of your Zenyard quota used so far",
                    clickable=False,
                    status="normal",
                )
            case UnlimitedUsage() | None:
                return UsageState("", "", False, "none")

    def _get_queue_position(self) -> ty.Optional[int]:
        state = self._model.runtime_status.binary_state
        if state is not None and isinstance(
            state.actual_instance, BinaryStateQueued
        ):
            return state.actual_instance.queue_position
        return None

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

    def _with_results_ready(self, label: str, ready_count: int) -> str:
        if ready_count > 0:
            return (
                f"{label} — {_format_compact_count(ready_count)} results ready"
            )
        return label

    def _get_analysis_progress_sync(self) -> ty.Optional[float]:
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

        return progress
