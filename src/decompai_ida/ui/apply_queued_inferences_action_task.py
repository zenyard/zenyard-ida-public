import ida_kernwin

from decompai_ida import ida_tasks
from decompai_ida.apply_inferences_task import ApplyInferencesTask
from decompai_ida.async_utils import wait_until_cancelled
from decompai_ida.model import Model
from decompai_ida.tasks import Task

ACTION_ID = "zenyard:apply_queued_inferences"


class _ApplyQueuedInferencesActionHandler(ida_kernwin.action_handler_t):
    """Action handler for applying queued results."""

    def __init__(self, model: Model):
        super().__init__()
        self._model = model

    def activate(self, ctx):  # type: ignore
        """Handle action activation - queue apply inferences task."""
        self._model.runtime_status.queue_foreground_task_if_not_already_queued(
            ApplyInferencesTask()
        )
        self._model.notify_update()
        return 1

    def update(self, ctx):  # type: ignore
        """Update action state - enable only when there are queued results."""
        if self._model.inference_queue.size_sync() > 0:
            return ida_kernwin.AST_ENABLE
        else:
            return ida_kernwin.AST_DISABLE


class ApplyQueuedInferencesActionTask(Task):
    """
    Task that manages the apply queued inferences action.
    """

    async def _run(self) -> None:
        async with ida_tasks.install_action(
            action_id=ACTION_ID,
            label="Apply Pending Results",
            handler=_ApplyQueuedInferencesActionHandler(self._ctx.model),
        ):
            await ida_tasks.run_ui(
                lambda: ida_kernwin.attach_action_to_menu(
                    "Zenyard/Open SwiftGlow",
                    ACTION_ID,
                    ida_kernwin.SETMENU_APP,
                )
            )
            await wait_until_cancelled()
