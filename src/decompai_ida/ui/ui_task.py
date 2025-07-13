import typing as ty
from contextlib import asynccontextmanager

import anyio
from PyQt5.QtWidgets import QApplication, QMainWindow, QStatusBar

from decompai_ida import ida_tasks, logger
from decompai_ida.apply_inferences_task import ApplyInferencesTask
from decompai_ida.queue_revisions_task import QueueRevisionsTask
from decompai_ida.status_bar_widget import StatusBarWidget
from decompai_ida.tasks import Task
from decompai_ida.ui.status_bar_view_model import StatusBarViewModel

_current_widget: ty.Optional[StatusBarWidget] = None
"Current widget in status bar, only present to allow interactive access"


class UiTask(Task):
    async def _run(self) -> None:
        view_model = StatusBarViewModel(self._ctx.model)
        next_update: ty.Awaitable[None] = anyio.sleep(0)
        try:
            async with self._status_bar_widget(view_model):
                while True:
                    # Capture the update event before working on emitting state, to
                    # ensure we never miss an update.
                    with anyio.move_on_after(1):
                        await next_update
                    next_update = self._ctx.model.wait_for_update()
                    await view_model.emit_current_state()
        finally:
            # Avoid warning about dropped coroutine.
            next_update.close()

    @asynccontextmanager
    async def _status_bar_widget(self, view_model: StatusBarViewModel):
        global _current_widget

        upload_callback = ida_tasks.AsyncCallback(self._on_upload_clicked)
        save_results_callback = ida_tasks.AsyncCallback(
            self._on_save_results_clicked
        )

        def setup_sync():
            status_bar = _find_status_bar_sync()
            widget = StatusBarWidget(view_model)
            widget.upload_clicked.connect(upload_callback)
            widget.save_results_clicked.connect(save_results_callback)
            status_bar.addPermanentWidget(widget)
            return status_bar, widget

        status_bar, widget = await ida_tasks.run_ui(setup_sync)

        try:
            _current_widget = widget
            yield
        finally:
            _current_widget = None
            with anyio.CancelScope(shield=True):
                await ida_tasks.run_ui(status_bar.removeWidget, widget)

    async def _on_upload_clicked(self):
        await logger.get().ainfo("Upload requested")
        self._ctx.model.runtime_status.queue_foreground_task_if_not_already_queued(
            QueueRevisionsTask
        )
        self._ctx.model.notify_update()

    async def _on_save_results_clicked(self):
        await logger.get().ainfo("Save results requested")
        self._ctx.model.runtime_status.queue_foreground_task_if_not_already_queued(
            ApplyInferencesTask
        )
        self._ctx.model.notify_update()


def _find_status_bar_sync() -> QStatusBar:
    for widget in QApplication.topLevelWidgets():
        if isinstance(widget, QMainWindow):
            return widget.statusBar()
    raise Exception("Can't find status bar")
