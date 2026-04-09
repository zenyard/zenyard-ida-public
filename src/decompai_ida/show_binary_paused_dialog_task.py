from decompai_client import (
    QuotaExhaustedDialogShownEvent,
    QuotaExhaustedDialogShownReason,
)

from decompai_ida import logger, messages
from decompai_ida.analytics_task import analytics_timestamp
from decompai_ida.tasks import Task, TaskContext


class ShowBinaryPausedDialogTask(Task):
    """
    Task that displays binary paused message dialog when binary first becomes
    paused.
    """

    def __init__(self, task_context: TaskContext):
        super().__init__(task_context)

    async def _run(self) -> None:
        """Watch model and show dialog when binary becomes paused."""

        if await self._ctx.model.paused_dialog_shown.get():
            await logger.adebug("Paused dialog already shown, stopping task")
            return

        while True:
            if self._ctx.model.is_considered_paused:
                await logger.get().ainfo("Binary paused - showing dialog")
                await self._ctx.model.paused_dialog_shown.set(True)
                await self._show_message_sync()
                return

            await self._ctx.model.wait_for_update()

    async def _show_message_sync(self):
        await self._ctx.model.paused_dialog_shown.set(True)
        user_response = await messages.warn_plan_ended()
        self._ctx.emit_analytics_event(
            QuotaExhaustedDialogShownEvent(
                timestamp=analytics_timestamp(),
                user_response=user_response,
                show_reason=QuotaExhaustedDialogShownReason.AUTOMATIC,
            )
        )
