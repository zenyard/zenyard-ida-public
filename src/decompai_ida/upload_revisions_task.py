import typing as ty

from decompai_client import (
    AddObjectsToCurrentRevisionParams,
    CreateRevisionParams,
    FinishAndAnalyzeCurrentRevisionParams,
    Object as ApiObject,
)
from decompai_ida import ida_tasks, logger
from decompai_ida.model import Object
from decompai_ida.tasks import Task


class UploadRevisionsTask(Task):
    async def _run(self):
        await self._ctx.model.wait_for_registration()
        while True:
            await self._wait_for_revision()
            await logger.adebug("Starting to upload queued revisions")
            with self._ctx.model.report_and_notify_background_task("uploading"):
                while (await self._ctx.model.revision_queue.size()) > 0:
                    await self._upload_revision()
            await logger.adebug("Done uploading queued revisions")

    async def _upload_revision(self):
        revisions = await self._ctx.model.revision_queue.peek(1)
        assert len(revisions) == 1
        revision = revisions[0]
        if revision is None:
            # Unreadable
            await logger.awarning("Skipping unreadable queued revision")
            await self._ctx.model.revision_queue.pop()
            self._ctx.model.notify_update()
            return

        binary_id = await self._ctx.model.binary_id.get()
        assert binary_id is not None

        next_revision = (await self._ctx.model.revision.get()) + 1
        analyze_dependents = not revision.is_initial_analysis

        log = logger.bind(
            revision=next_revision,
            analyze_dependents=analyze_dependents,
            object_count=len(revision.objects),
        )
        await log.adebug("Uploading revision")

        await self._retry_api_request_forever(
            lambda: self._ctx.binaries_api.create_revision(
                binary_id=binary_id,
                create_revision_params=CreateRevisionParams(
                    number=next_revision
                ),
            ),
            description=f"Create revision {next_revision}",
        )

        for i, chunk in enumerate(
            self._split_to_uploadable_chunks(revision.objects)
        ):
            await log.adebug(
                "Uploading chunk", objects_in_chunk=len(chunk), chunk_index=i
            )
            await self._retry_api_request_forever(
                lambda: self._ctx.binaries_api.add_objects_to_current_revision(
                    binary_id=binary_id,
                    add_objects_to_current_revision_params=AddObjectsToCurrentRevisionParams(
                        objects=chunk,
                    ),
                ),
                description=(
                    f"Upload chunk #{i+1} with {len(chunk)} objects to revision {next_revision}"
                ),
            )

        await log.adebug("Finishing revision")
        await self._retry_api_request_forever(
            lambda: self._ctx.binaries_api.finish_and_analyze_current_revision(
                binary_id=binary_id,
                finish_and_analyze_current_revision_params=FinishAndAnalyzeCurrentRevisionParams(
                    analyze_dependents=analyze_dependents,
                ),
            ),
            description=f"Finish revision {next_revision}",
        )

        # Update queue and current revision together to avoid showing wrong
        # state in UI for a moment.
        await ida_tasks.run(self._update_revision_atomically_sync)
        self._ctx.model.notify_update()

        await log.ainfo("Uploaded revision")

    async def _wait_for_revision(self):
        while (await self._ctx.model.revision_queue.size()) == 0:
            await self._ctx.model.wait_for_update()

    def _update_revision_atomically_sync(self):
        self._ctx.model.revision.set_sync(
            self._ctx.model.revision.get_sync() + 1
        )
        self._ctx.model.revision_queue.pop_sync()

    def _split_to_uploadable_chunks(
        self, objects: ty.Iterable[Object]
    ) -> ty.Iterable[list[ApiObject]]:
        current_chunk: list[ApiObject] = []
        current_chunk_bytes = 0

        for obj in objects:
            object_size = len(obj.model_dump_json().encode("utf-8"))

            if len(current_chunk) > 0 and (
                current_chunk_bytes + object_size
                > self._ctx.static_config.max_upload_bytes
            ):
                yield list(current_chunk)
                current_chunk.clear()
                current_chunk_bytes = 0

            current_chunk.append(ApiObject(obj))
            current_chunk_bytes += object_size

        if len(current_chunk) > 0:
            yield current_chunk
