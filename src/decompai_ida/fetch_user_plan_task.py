import anyio

from decompai_ida import logger
from decompai_ida.tasks import Task

_POLL_INTERVAL_SECONDS = 5


class FetchUserPlanTask(Task):
    async def _run(self) -> None:
        await self._ctx.model.wait_for_user_config()
        user_plans_usage = None
        while True:
            try:
                usage_response = await self._retry_api_request_forever(
                    lambda: self._ctx.user_api.get_user_plans_usage(),
                    description="Get user current usage",
                )

                user_plans_usage = (
                    usage_response.actual_instance if usage_response else None
                )

                await logger.ainfo(
                    "Got user current usage",
                    user_plans_usage=user_plans_usage,
                )

            except Exception as ex:
                await logger.awarning(
                    "Error while fetching user plan, will retry",
                    exc_info=ex,
                )

            self._ctx.model.runtime_status.user_plans_usage = user_plans_usage

            self._ctx.model.notify_update()

            # Wait before next poll
            await anyio.sleep(_POLL_INTERVAL_SECONDS)
