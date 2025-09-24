from decompai_client import UserConfig
from decompai_ida import logger
from decompai_ida.tasks import Task


class FetchUserConfigTask(Task):
    async def _run(self) -> None:
        try:
            user_config = await self._retry_api_request_forever(
                lambda: self._ctx.user_api.get_user_config(),
                description="Get user configuration",
            )

            # Not logging entire configuration since it contains secrets.
            await logger.ainfo(
                "Got user configuration",
                max_binary_size_mb=user_config.max_binary_size_mb,
                has_copilot=user_config.copilot is not None,
            )

        except Exception as ex:
            # This is not an "active task", and other non-active tasks are
            # waiting for user configuration, so we fall back to defaults to
            # allow these to function.
            await logger.awarning(
                "Error while fetching user config, falling back to defaults",
                exc_info=ex,
            )
            user_config = UserConfig()

        self._ctx.model.runtime_status.user_config = user_config
        self._ctx.model.notify_update()
