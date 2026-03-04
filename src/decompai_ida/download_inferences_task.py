import anyio

from decompai_client import Inference
from decompai_ida import logger
from decompai_ida.tasks import Task

_POLL_INTERVAL = 1
_MAX_INFERENCES_IN_ONE_REQUEST = 50


class DownloadInferencesTask(Task):
    async def _run(self):
        await self._ctx.model.wait_for_registration()
        while True:
            with self._ctx.model.report_and_notify_background_task(
                "downloading"
            ):
                await self._fetch_inferences()
            await self._wait_for_new_revision()

    async def _wait_for_new_revision(self):
        await logger.adebug("Waiting for new revision")
        current_revision = await self._ctx.model.revision.get()
        while current_revision == (await self._ctx.model.revision.get()):
            await self._ctx.model.wait_for_update()

    async def _fetch_inferences(self):
        binary_id = await self._ctx.model.binary_id.get()
        assert binary_id is not None

        cursor = await self._ctx.model.inference_cursor.get()

        while True:
            server_revision = await self._ctx.model.server_revision.get()
            current_revision = await self._ctx.model.revision.get()

            log = logger.bind(
                revision=current_revision,
                server_revision=server_revision,
                cursor=cursor,
            )

            await log.adebug("Getting inference page")

            result = await self._retry_api_request_forever(
                lambda: self._ctx.binaries_api.get_inferences(
                    binary_id=binary_id,
                    revision_number=current_revision,
                    cursor=cursor,
                    limit=_MAX_INFERENCES_IN_ONE_REQUEST,
                ),
            )

            await log.adebug(
                "Got inferences",
                count=len(result.inferences),
                new_cursor=result.cursor,
            )

            for inference in result.inferences:
                if (
                    isinstance(inference.actual_instance, Inference)
                    and inference.actual_instance.actual_instance is not None
                ):
                    await self._ctx.model.push_inference(
                        inference.actual_instance.actual_instance
                    )
                else:
                    await logger.awarning(
                        "Ignoring unknown inference type",
                        inference=inference.actual_instance,
                    )

            cursor = result.cursor
            await self._ctx.model.inference_cursor.set(cursor)
            self._ctx.model.notify_update()

            # Local revision may have progressed while downloading.
            current_revision = await self._ctx.model.revision.get()
            log = log.bind(revision=current_revision)

            if result.has_next:
                await log.adebug("Fetching more inferences immediately")

            elif server_revision == current_revision:
                await log.ainfo("Done fetching inferences")
                return

            else:
                await log.adebug(
                    "Will try fetching more inferences after poll interval"
                )
                await anyio.sleep(_POLL_INTERVAL)
