import time
import anyio

from decompai_client import (
    BinaryAnalysisIdle,
    BinaryAnalysisInProgress,
)
from decompai_ida import logger
from decompai_ida.model import RemoteAnalysisStats
from decompai_ida.tasks import Task

_POLL_INTERVAL = 3


class PollServerStatusTask(Task):
    async def _run(self):
        await self._ctx.model.wait_for_registration()

        while True:
            if await self._is_client_in_sync_with_server():
                await self._ctx.model.last_done_revision.set(
                    await self._ctx.model.revision.get()
                )

                if self._ctx.model.runtime_status.remote_analysis_stats:
                    stats = self._ctx.model.runtime_status.remote_analysis_stats
                    await logger.ainfo(
                        "Server analysis complete",
                        duration_seconds=time.monotonic() - stats.start_time,
                    )

                self._ctx.model.runtime_status.remote_analysis_stats = None

                self._ctx.model.notify_update()
                await self._wait_for_client_to_be_ahead_of_server()

            new_server_revision = await self._poll_server()
            if self._ctx.model.runtime_status.remote_analysis_stats is None:
                self._ctx.model.runtime_status.remote_analysis_stats = (
                    RemoteAnalysisStats(
                        start_time=time.monotonic(),
                        start_revision=new_server_revision,
                    )
                )
                self._ctx.model.notify_update()

            if new_server_revision != (
                await self._ctx.model.server_revision.get()
            ):
                await logger.ainfo(
                    "Server revision updated",
                    new_server_revision=new_server_revision,
                )
                await self._ctx.model.server_revision.set(new_server_revision)
                self._ctx.model.notify_update()

            await anyio.sleep(_POLL_INTERVAL)

    async def _wait_for_client_to_be_ahead_of_server(self):
        while await self._is_client_in_sync_with_server():
            await self._ctx.model.wait_for_update()

    async def _is_client_in_sync_with_server(self):
        return (await self._ctx.model.revision.get()) == (
            await self._ctx.model.server_revision.get()
        )

    async def _poll_server(self) -> float:
        binary_id = await self._ctx.model.binary_id.get()
        assert binary_id is not None

        revision = await self._ctx.model.revision.get()
        response = await self._retry_api_request_forever(
            lambda: self._ctx.binaries_api.get_status(binary_id=binary_id),
        )
        status = response.actual_instance

        log = logger.bind(local_revision=revision)

        if isinstance(status, BinaryAnalysisIdle):
            # Server completed at least the revision stored in DB
            # before calling API.
            progress = revision
            log = log.bind(server_status="idle")
        elif isinstance(status, BinaryAnalysisInProgress):
            progress = status.revision - 1 + status.progress
            log = log.bind(
                server_status="in_progress",
                server_revision=status.revision,
                server_progress=status.progress,
            )
        else:
            raise Exception(f"Unknown status: {status}")

        await log.adebug("Got server status", progress=progress)

        return progress
