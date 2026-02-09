import typing as ty

import ida_bytes
import ida_loader
import ida_segment
import idautils
import structlog
import zstandard
from anyio import to_thread

from decompai_client import (
    AddObjectsToCurrentRevisionParams,
    CreateRevisionParams,
    FinishAndAnalyzeCurrentRevisionBody,
    Section,
)
from decompai_client import Object as ApiObject
from decompai_ida import api, ida_tasks, logger
from decompai_ida.tasks import Task

_MAX_SECTION_DATA_SIZE = 10 * 1024 * 1024
_ZSTD_COMPRESSOR = zstandard.ZstdCompressor(level=6, threads=0)

_MAX_RETRIES_FOR_REVISION_REQUEST = 5


def _read_sections_sync() -> list[Section]:
    sections: list[Section] = []
    for address in idautils.Segments():
        seg = ida_segment.getseg(address)
        if seg is None:
            continue
        sections.append(
            Section(
                address=api.format_address(seg.start_ea),
                name=ida_segment.get_segm_name(seg),
                size=seg.end_ea - seg.start_ea,
                class_="other",
                read=bool(seg.perm & ida_segment.SEGPERM_READ),
                write=bool(seg.perm & ida_segment.SEGPERM_WRITE),
                execute=bool(seg.perm & ida_segment.SEGPERM_EXEC),
            )
        )
    return sections


def _try_read_section_data_sync(section: Section) -> ty.Optional[bytes]:
    start_ea = api.parse_address(section.address)
    seg = ida_segment.getseg(start_ea)
    if seg is None:
        return None
    if section.size >= _MAX_SECTION_DATA_SIZE:
        return None
    if ida_loader.get_fileregion_offset(seg.start_ea) < 0:
        return None
    return ida_bytes.get_bytes(seg.start_ea, section.size)


class UploadSectionsTask(Task):
    async def _run(self) -> None:
        await self._ctx.model.wait_for_registration()
        await logger.adebug("Waiting for ready for analysis")
        await self._ctx.model.wait_for_ready_for_analysis()

        if await self._ctx.model.sections_uploaded.get():
            await logger.adebug("Sections already uploaded")
            return

        with self._ctx.model.report_and_notify_background_task("uploading"):
            try:
                try:
                    await self._retry_api_request_forever(
                        lambda: self._upload_sections(),
                        description="Upload sections",
                    )
                except Exception as ex:
                    await logger.awarning(
                        "Failed uploading sections", exc_info=ex
                    )
                await self._ctx.model.sections_uploaded.set(True)
                self._ctx.model.notify_update()
                await logger.ainfo("Sections uploaded successfully")
            except Exception as ex:
                await logger.awarning(
                    "Error while uploading sections", exc_info=ex
                )

    async def _upload_sections(self) -> None:
        binary_id = await self._ctx.model.binary_id.get()
        assert binary_id is not None

        next_revision = (await self._ctx.model.revision.get()) + 1
        all_sections = await ida_tasks.run(_read_sections_sync)

        # Filter out sections that are excluded from upload
        sections = [
            section
            for section in all_sections
            if not await self._ctx.model.sections_excluded_from_upload.get(
                api.parse_address(section.address)
            )
        ]

        if not sections:
            await logger.adebug("No sections found; skipping upload")
            return

        for section in sections:
            await logger.ainfo(
                "Found section",
                address=section.address,
                name=section.name,
                size=section.size,
                read=section.read,
                write=section.write,
                execute=section.execute,
            )

        with structlog.contextvars.bound_contextvars(
            revision=next_revision, section_count=len(sections)
        ):
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
            objects = [ApiObject(section) for section in sections]
            await self._retry_api_request_forever(
                lambda: self._ctx.binaries_api.add_objects_to_current_revision(
                    binary_id=binary_id,
                    add_objects_to_current_revision_params=AddObjectsToCurrentRevisionParams(
                        objects=objects
                    ),
                ),
                description="Upload section metadata",
                max_retries=_MAX_RETRIES_FOR_REVISION_REQUEST,
            )
            for section in sections:
                data = await ida_tasks.run(_try_read_section_data_sync, section)
                if data is None:
                    continue
                compressed_data = await to_thread.run_sync(
                    _ZSTD_COMPRESSOR.compress, data
                )
                await logger.ainfo(
                    "Uploading section data",
                    name=section.name,
                    size=len(data),
                    compressed_size=len(compressed_data),
                )
                await self._retry_api_request_forever(
                    lambda section=section,
                    compressed_data=compressed_data: self._ctx.binaries_api.set_large_data_to_object(
                        address=section.address,
                        binary_id=binary_id,
                        compressed_data=compressed_data,
                    ),
                    description=f"Upload data for section {section.name}",
                    max_retries=_MAX_RETRIES_FOR_REVISION_REQUEST,
                )

            await self._retry_api_request_forever(
                lambda: self._ctx.binaries_api.finish_and_analyze_current_revision(
                    binary_id=binary_id,
                    finish_and_analyze_current_revision_body=FinishAndAnalyzeCurrentRevisionBody(
                        analyze_dependents=False,
                        swift_only=False,
                    ),
                ),
                description=f"Finish revision {next_revision}",
                max_retries=_MAX_RETRIES_FOR_REVISION_REQUEST,
            )

            await ida_tasks.run(self._increase_revision_sync)
            self._ctx.model.notify_update()

    def _increase_revision_sync(self) -> None:
        self._ctx.model.revision.set_sync(
            self._ctx.model.revision.get_sync() + 1
        )
