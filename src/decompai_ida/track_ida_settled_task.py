"""
Sets the `ida_settled` flag at model when IDA has been quiet for enough time.
"""

import anyio

from decompai_ida import events, logger
from decompai_ida.async_utils import wait_for_object_of_type
from decompai_ida.tasks import Task

_SETTLING_TIME = 5
"""
Seconds without changes until we assume IDA is settled.
"""

_UNSETTLED_EVENTS = (
    events.AddressModified,
    events.LocalTypeChanged,
)
"""
Events showing that IDA has not yet settled.
"""


class TrackIdaSettledTask(Task):
    async def _run(self) -> None:
        await logger.adebug("Waiting for auto analysis")
        await self._ctx.model.wait_for_initial_analysis()

        while True:
            await logger.adebug(
                "Waiting for IDA to be unsettled with no foreground task"
            )
            await self._wait_for_ida_to_be_unsettled_and_no_foreground_task()

            await logger.adebug("Waiting for IDA to settle")
            await self._wait_for_ida_to_settle()

            await logger.adebug("IDA settled")
            self._ctx.model.runtime_status.ida_settled = True
            self._ctx.model.notify_update()

    async def _wait_for_ida_to_be_unsettled_and_no_foreground_task(self):
        while (
            self._ctx.model.runtime_status.ida_settled
            or self._ctx.model.runtime_status.foreground_task_active
        ):
            await self._ctx.model.wait_for_update()

    async def _wait_for_ida_to_settle(self):
        settled = False

        async with self._ctx.ida_events.subscribe(
            replay_recorded=False
        ) as ida_events:
            while not settled:
                settled = True
                with anyio.move_on_after(_SETTLING_TIME):
                    await wait_for_object_of_type(
                        ida_events, *_UNSETTLED_EVENTS
                    )
                    settled = False
