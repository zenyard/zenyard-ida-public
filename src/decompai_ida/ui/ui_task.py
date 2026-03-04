import typing as ty
from contextlib import asynccontextmanager

import anyio
from qtpy.QtWidgets import QApplication, QMainWindow

from decompai_ida import ida_tasks, logger, messages
from decompai_ida.apply_inferences_task import ApplyInferencesTask
from decompai_ida.ask_initial_questions_task import ShowInitialQuestionsTask
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
        usage_callback = ida_tasks.AsyncCallback(self._on_usage_clicked)

        def setup_sync():
            main_window = _find_main_window()
            widget = StatusBarWidget(view_model)
            widget.upload_clicked.connect(upload_callback)
            widget.save_results_clicked.connect(save_results_callback)
            widget.usage_clicked.connect(usage_callback)
            main_window.statusBar().addPermanentWidget(widget)
            return main_window, widget

        main_window, widget = await ida_tasks.run_ui(setup_sync)

        try:
            _current_widget = widget
            yield
        finally:
            _current_widget = None
            with anyio.CancelScope(shield=True):
                await ida_tasks.run_ui(
                    lambda: main_window.statusBar().removeWidget(widget)
                )

    async def _on_upload_clicked(self):
        await logger.get().ainfo("Upload requested")
        if await self._ctx.model.asked_initial_questions.get():
            self._ctx.model.runtime_status.queue_foreground_task_if_not_already_queued(
                QueueRevisionsTask()
            )
        else:
            self._ctx.model.runtime_status.queue_foreground_task_if_not_already_queued(
                ShowInitialQuestionsTask()
            )
        self._ctx.model.notify_update()

    async def _on_save_results_clicked(self):
        await logger.get().ainfo("Save results requested")
        self._ctx.model.runtime_status.queue_foreground_task_if_not_already_queued(
            ApplyInferencesTask()
        )
        self._ctx.model.notify_update()

    async def _on_usage_clicked(self):
        """Handle click on usage label - show binary paused dialog."""
        await messages.warn_plan_ended()


def _find_main_window() -> QMainWindow:
    for widget in QApplication.topLevelWidgets():
        if isinstance(widget, QMainWindow):
            return widget
    raise Exception("Can't find main window")
