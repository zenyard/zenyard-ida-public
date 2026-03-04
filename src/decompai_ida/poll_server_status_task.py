from dataclasses import dataclass
import anyio
import typing as ty

from decompai_client.models.binary_state import BinaryState
from decompai_ida import logger
from decompai_ida.tasks import Task, TaskContext


@dataclass(frozen=True)
class _ServerStatus:
    revision: float
    state: BinaryState


_POLL_INTERVAL = 3


class PollServerStatusTask(Task):
    def __init__(self, task_context: TaskContext):
        super().__init__(task_context)
        self._max_server_version: ty.Optional[int] = None

    async def _run(self):
        await self._ctx.model.wait_for_registration()

        while True:
            if await self._is_client_in_sync_with_server():
                await self._ctx.model.last_done_revision.set(
                    await self._ctx.model.revision.get()
                )

                self._max_server_version = None
                self._ctx.model.notify_update()
                await self._wait_for_client_to_be_ahead_of_server()

            server_status = await self._poll_server()

            if (
                self._ctx.model.runtime_status.binary_state
                != server_status.state
            ):
                self._ctx.model.runtime_status.binary_state = (
                    server_status.state
                )
                self._ctx.model.notify_update()

            if server_status.revision != (
                await self._ctx.model.server_revision.get()
            ):
                await logger.ainfo(
                    "Server revision updated",
                    new_server_revision=server_status.revision,
                )
                await self._ctx.model.server_revision.set(
                    server_status.revision
                )
                self._ctx.model.notify_update()

            await anyio.sleep(_POLL_INTERVAL)

    async def _wait_for_client_to_be_ahead_of_server(self):
        while await self._is_client_in_sync_with_server():
            await self._ctx.model.wait_for_update()

    async def _is_client_in_sync_with_server(self):
        return (await self._ctx.model.revision.get()) == (
            await self._ctx.model.server_revision.get()
        )

    async def _poll_server(self) -> _ServerStatus:
        binary_id = await self._ctx.model.binary_id.get()
        assert binary_id is not None

        local_revision = await self._ctx.model.revision.get()
        status = await self._retry_api_request_forever(
            lambda: self._ctx.binaries_api.get_detailed_status(
                binary_id=binary_id
            ),
        )
        self._ctx.model.notify_update()

        log = logger.bind(local_revision=local_revision)

        if len(status.revision_analyses) > 0:
            current_target_revision = max(
                analysis.revision for analysis in status.revision_analyses
            )
            self._max_server_version = max(
                current_target_revision, self._max_server_version or 0
            )
            missing_progress = sum(
                (1.0 - analysis.progress)
                for analysis in status.revision_analyses
            )
            log = log.bind(
                server_status="in_progress",
                server_target_revision=self._max_server_version,
                server_missing_progress=missing_progress,
            )
            server_revision = self._max_server_version - missing_progress
        else:
            # Server completed at least the revision stored in DB
            # before calling API.
            server_revision = local_revision
            log = log.bind(server_status="idle")

        await log.adebug("Got server status", server_revision=server_revision)

        return _ServerStatus(revision=server_revision, state=status.state)
