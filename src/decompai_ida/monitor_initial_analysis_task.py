import anyio
import ida_auto

from decompai_ida import events, ida_tasks
from decompai_ida.async_utils import wait_for_object_of_type
from decompai_ida.tasks import Task


class MonitorInitialAnalysisTask(Task):
    async def _run(self):
        assert not self._ctx.model.runtime_status.initial_analysis_complete

        # Note - not reporting anything to UI here. It's deferred to any task
        # is actually waiting on `initial_analysis_complete` before doing
        # anything visible to user.

        # Wait for auto analysis to start.
        await anyio.sleep(1)

        async with self._ctx.ida_events.subscribe() as event_receiver:
            while not (await ida_tasks.run(ida_auto.auto_is_ok)):
                with anyio.move_on_after(3):
                    await wait_for_object_of_type(
                        event_receiver,
                        events.InitialAutoAnalysisComplete,
                    )

                    # Wait to see if auto analysis restarts
                    await anyio.sleep(1)

        # Wait for IDA to settle.
        await anyio.sleep(1)

        self._ctx.model.runtime_status.initial_analysis_complete = True
        self._ctx.model.notify_update()
