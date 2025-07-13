from contextlib import contextmanager

import anyio

from decompai_ida import ida_tasks, logger
from decompai_ida.events import block_ida_events
from decompai_ida.tasks import Task
from decompai_ida.wait_box import Cancelled, WaitBox


class StartForegroundTasksTask(Task):
    async def _run(self):
        while True:
            while (
                len(self._ctx.model.runtime_status.foreground_task_queue) == 0
            ):
                await self._ctx.model.wait_for_update()

            # Don't start any foreground task while IDA is analyzing and settling.
            with self._ctx.model.report_and_notify_background_task(
                "waiting_for_ida"
            ):
                await self._ctx.model.wait_for_initial_analysis()
                await self._wait_for_ida_to_settle()

            # Let UI update (stop showing "waiting for IDA") before hanging it with wait box.
            await anyio.sleep(0.5)

            with self._report_foreground_task_active():
                await ida_tasks.run(self._run_queued_tasks)

    def _run_queued_tasks(self):
        with block_ida_events(), WaitBox("Starting...") as wait_box:
            self._ctx.model.runtime_status.foreground_task_active = True
            self._ctx.model.runtime_status.ida_settled = False
            self._ctx.model.notify_update()

            while len(self._ctx.model.runtime_status.foreground_task_queue) > 0:
                task_type = self._ctx.model.runtime_status.foreground_task_queue.popleft()
                self._ctx.model.notify_update()

                log = logger.bind(
                    task=task_type.__name__,
                    remaining_tasks=[
                        remaining_task.__name__
                        for remaining_task in self._ctx.model.runtime_status.foreground_task_queue
                    ],
                )

                try:
                    log.debug("Starting foreground task")
                    task_instance = task_type(self._ctx, wait_box)
                    task_instance.run()

                except Cancelled:
                    log.info("Foreground tasks cancelled by user")
                    # Don't start any more foreground tasks if user cancelled.
                    self._ctx.model.runtime_status.foreground_task_queue.clear()
                    self._ctx.model.notify_update()

                except Exception as ex:
                    log.warning("Foreground task failed", exc_info=ex)

    @contextmanager
    def _report_foreground_task_active(self):
        self._ctx.model.runtime_status.foreground_task_active = True
        self._ctx.model.notify_update()
        try:
            yield
        finally:
            self._ctx.model.runtime_status.foreground_task_active = False
            self._ctx.model.notify_update()

    async def _wait_for_ida_to_settle(self):
        while not self._ctx.model.runtime_status.ida_settled:
            await self._ctx.model.wait_for_update()
