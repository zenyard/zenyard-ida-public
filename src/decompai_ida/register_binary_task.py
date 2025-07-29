import ida_kernwin

from decompai_client import BinaryDetails, PostBinaryBody
from decompai_ida import binary, ida_tasks, logger
from decompai_ida.tasks import Task


class BinaryExceedsSizeLimitError(Exception):
    def __init__(self, *, max_binary_size_mb: int) -> None:
        super().__init__("Binary exceeds size limit")
        self.max_binary_size_mb = max_binary_size_mb


class RegisterBinaryTask(Task):
    async def _run(self):
        if (await self._ctx.model.binary_id.get()) is not None:
            await logger.adebug("Already registered")
            return

        await logger.adebug("Registering binary")
        await self._verify_binary_allowed()

        binary_path = await ida_tasks.run(binary.get_binary_path_sync)

        if self._ctx.plugin_config.ask_for_binary_instructions:
            binary_instructions = await ida_tasks.run(
                ida_kernwin.ask_text,
                10_000,
                "",
                "Enter instructions for this database",
            )
        else:
            binary_instructions = None

        post_body = PostBinaryBody(
            name=binary_path.name,
            details=BinaryDetails(instructions=binary_instructions),
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

    async def _verify_binary_allowed(self):
        user_config = await self._ctx.model.wait_for_user_config()
        assert user_config.max_binary_size_mb is not None
        binary_bytes = await ida_tasks.run(binary.get_size_sync)
        if binary_bytes > user_config.max_binary_size_mb * 2**20:
            raise BinaryExceedsSizeLimitError(
                max_binary_size_mb=user_config.max_binary_size_mb
            )
