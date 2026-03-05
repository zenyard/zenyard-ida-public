import ida_nalt

from decompai_client import (
    BinaryDetails,
    OriginalLanguages,
    PostBinaryBody,
    Decompiler,
)
from decompai_client.models.decompiler_type import DecompilerType
from decompai_ida import binary, ida_tasks, logger
from decompai_ida.tasks import CriticalTaskError, Task


async def extract_platform_and_os_version():
    platform = None
    os_version = None
    try:
        platform, os_version = await ida_tasks.run(
            binary.get_platform_and_os_version_sync
        )
    except Exception as ex:
        await logger.awarning(
            "Something went wrong in platform and os version extraction",
            exc_info=ex,
        )

    return (platform, os_version)


class BinaryExceedsSizeLimitError(CriticalTaskError):
    def __init__(self, *, max_binary_size_mb: int) -> None:
        super().__init__("Binary exceeds size limit")
        self.max_binary_size_mb = max_binary_size_mb


class RegisterBinaryTask(Task):
    async def _run(self) -> None:
        if (await self._ctx.model.binary_id.get()) is not None:
            await logger.adebug("Already registered")
            return

        await logger.adebug("Waiting for auto analysis")
        await self._ctx.model.wait_for_initial_analysis()

        await logger.adebug("Waiting for initial questions")
        await self._ctx.model.wait_for_initial_questions()

        await logger.adebug("Registering binary")

        binary_path = await ida_tasks.run(binary.get_binary_path_sync)
        binary_instructions = await self._ctx.model.binary_instructions.get()
        if (
            binary_instructions is not None
            and binary_instructions.strip() == ""
        ):
            binary_instructions = None

        has_swift = False
        if await ida_tasks.run(ida_nalt.get_abi_name) == "swift":
            has_swift = True

        platform, os_version = await extract_platform_and_os_version()
        input_file_sha256 = await ida_tasks.run(
            ida_nalt.retrieve_input_file_sha256
        )
        post_body = PostBinaryBody(
            name=binary_path.name,
            details=BinaryDetails(
                instructions=binary_instructions,
                original_languages=OriginalLanguages(swift=has_swift),
                platform=platform,
                os_version=os_version,
                input_file_sha256=input_file_sha256.hex(),
                decompiler=Decompiler(type=DecompilerType.IDA),
            ),
        )

        with self._ctx.model.report_and_notify_background_task("registering"):
            result = await self._retry_api_request_forever(
                lambda: self._ctx.binaries_api.create_binary(post_body),
            )

        await logger.ainfo(
            "Binary successfully registered", binary_id=result.binary_id
        )
        await self._ctx.model.binary_id.set(result.binary_id)
        self._ctx.model.notify_update()
