import anyio

from decompai_ida import ida_tasks, logger
from decompai_ida.apply_inferences_task import ApplyInferencesTask
from decompai_ida.model import TaskName
from decompai_ida.tasks import Task


class TriggerApplyInferencesTask(Task):
    """
    Queues `ApplyInferences` when `apply_inferences_when_ready` is set and
    server completed analysis.
    """

    async def _run(self):
        while True:
            # Ensure download inferences task has a chance to start.
            await anyio.sleep(0.1)
            if await ida_tasks.run(self._should_trigger_sync):
                await logger.ainfo("Triggering apply inferences")
                self._ctx.model.runtime_status.queue_foreground_task_if_not_already_queued(
                    ApplyInferencesTask()
                )
                self._ctx.model.runtime_status.apply_inferences_when_ready = (
                    False
                )
                self._ctx.model.notify_update()
            await self._ctx.model.wait_for_update()

    def _should_trigger_sync(self):
        downloading_task: TaskName = "downloading"  # For type safety

        server_finished_analyzing = (
            self._ctx.model.revision.get_sync()
            == self._ctx.model.server_revision.get_sync()
        )

        apply_requested = (
            self._ctx.model.runtime_status.apply_inferences_when_ready
        )

        not_currently_uploading = (
            self._ctx.model.revision_queue.size_sync() == 0
        )

        not_currently_downloading = (
            downloading_task not in self._ctx.model.runtime_status.active_tasks
        )

        no_foreground_tasks = (
            len(self._ctx.model.runtime_status.foreground_task_queue) == 0
            and not self._ctx.model.runtime_status.foreground_task_active
        )

        should_trigger = (
            server_finished_analyzing
            and apply_requested
            and not_currently_uploading
            and not_currently_downloading
            and no_foreground_tasks
        )

        logger.debug(
            "Considered triggering",
            server_finished_analyzing=server_finished_analyzing,
            apply_requested=apply_requested,
            not_currently_uploading=not_currently_uploading,
            not_currently_downloading=not_currently_downloading,
            no_foreground_tasks=no_foreground_tasks,
            should_trigger=should_trigger,
        )

        return should_trigger
