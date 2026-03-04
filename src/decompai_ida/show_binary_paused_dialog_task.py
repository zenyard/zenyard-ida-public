from decompai_ida import logger, messages
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
                await messages.warn_plan_ended()
                return

            await self._ctx.model.wait_for_update()
