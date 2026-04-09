import typing as ty

import structlog


from decompai_client import (
    AddObjectsToCurrentRevisionParams,
    CreateRevisionParams,
    FinishAndAnalyzeCurrentRevisionBody,
    Object as ApiObject,
)
from decompai_ida import ida_tasks, logger
from decompai_ida.model import Object
from decompai_ida.objects import validate_object
from decompai_ida.tasks import Task


_MAX_RETRIES_FOR_REVISION_REQUEST = 5


class UploadRevisionsTask(Task):
    async def _run(self):
        await self._ctx.model.wait_for_registration()
        await logger.adebug("Waiting for ready for analysis")
        await self._ctx.model.wait_for_ready_for_analysis()
        # Wait for section uploading to successfully finish.
        while (
            "uploading" in self._ctx.model.runtime_status.active_tasks
            or not await self._ctx.model.sections_uploaded.get()
        ):
            await self._ctx.model.wait_for_update()
        while True:
            await self._wait_for_revision()
            await logger.adebug("Starting to upload queued revisions")
            with self._ctx.model.report_and_notify_background_task("uploading"):
                while (await self._ctx.model.revision_queue.size()) > 0:
                    await self._retry_api_request_forever(
                        lambda: self._upload_revision(),
                        description="Upload revision",
                    )
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

        with structlog.contextvars.bound_contextvars(
            revision=next_revision,
            analyze_dependents=analyze_dependents,
            object_count=len(revision.objects),
        ):
            await logger.adebug("Uploading revision")

            await self._retry_api_request_forever(
                lambda: self._ctx.binaries_api.create_revision(
                    binary_id=binary_id,
                    create_revision_params=CreateRevisionParams(
                        number=next_revision
                    ),
                ),
                description=f"Create revision {next_revision}",
                max_retries=_MAX_RETRIES_FOR_REVISION_REQUEST,
            )

            valid_objects = await _drop_invalid_objects(revision.objects)
            chunks = self._split_to_uploadable_chunks(valid_objects)
            for i, chunk in enumerate(chunks):
                await logger.adebug(
                    "Uploading chunk",
                    objects_in_chunk=len(chunk),
                    chunk_index=i,
                )
                await self._retry_api_request_forever(
                    lambda: (
                        self._ctx.binaries_api.add_objects_to_current_revision(
                            binary_id=binary_id,
                            add_objects_to_current_revision_params=AddObjectsToCurrentRevisionParams(
                                objects=chunk,
                            ),
                        )
                    ),
                    description=(
                        f"Upload chunk #{i + 1} with {len(chunk)} objects to revision {next_revision}"
                    ),
                    max_retries=_MAX_RETRIES_FOR_REVISION_REQUEST,
                )

            await logger.adebug("Finishing revision")
            await self._retry_api_request_forever(
                lambda: (
                    self._ctx.binaries_api.finish_and_analyze_current_revision(
                        binary_id=binary_id,
                        finish_and_analyze_current_revision_body=FinishAndAnalyzeCurrentRevisionBody(
                            analyze_dependents=analyze_dependents,
                            swift_only=revision.swift_only,
                            perform_global_analysis=revision.perform_global_analysis,
                        ),
                    )
                ),
                description=f"Finish revision {next_revision}",
                max_retries=_MAX_RETRIES_FOR_REVISION_REQUEST,
            )

            # Update queue and current revision together to avoid showing wrong
            # state in UI for a moment.
            await ida_tasks.run(self._update_revision_atomically_sync)
            self._ctx.model.notify_update()

            await logger.ainfo("Uploaded revision")

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


async def _drop_invalid_objects(
    objects: ty.Iterable[Object],
) -> ty.Sequence[Object]:
    results = list[Object]()
    for obj in objects:
        try:
            validate_object(obj)
            results.append(obj)
        except Exception as ex:
            await logger.awarning(
                "Dropping invalid object", address=obj.address, exc_info=ex
            )
    return results
