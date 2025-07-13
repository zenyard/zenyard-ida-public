from decompai_ida import binary, logger
from decompai_ida.tasks import Task


class UploadOriginalFilesTask(Task):
    async def _run(self) -> None:
        if await self._ctx.model.original_files_uploaded.get():
            await logger.adebug("Original files already uploaded")
            return

        await self._ctx.model.wait_for_registration()

        try:
            await self._upload_original_files()
            await self._ctx.model.original_files_uploaded.set(True)
        except Exception as ex:
            await logger.awarning(
                "Error while uploading originals", exc_info=ex
            )
            # Not critical for plugin.

    async def _upload_original_files(self):
        binary_id = await self._ctx.model.binary_id.get()
        assert binary_id is not None
        input_file = await binary.read_compressed_input_file()
        await self._retry_api_request_forever(
            lambda: self._ctx.binaries_api.put_original_file(
                binary_id=binary_id,
                name=input_file.name,
                data=input_file.data,
            ),
        )
        await logger.ainfo(
            "Original files uploaded successfully",
            name=input_file.name,
            compressed_size_bytes=len(input_file.data),
        )
