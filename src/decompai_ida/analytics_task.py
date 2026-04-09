"""
Task that listens to analytics events and sends them to the backend.
"""

import functools
import platform
import typing as ty
import uuid
import anyio
import anyio.abc
import ida_kernwin

from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from decompai_client import AnalyticsApi
from decompai_client.models import (
    DatabaseOpenedEvent,
    DecompilerEnum,
    Event as AnalyticsEvent,
    ExtraDetails,
    OSEnum,
    PluginLoadedEvent,
    TrackEventRequest,
)
from decompai_ida import binary, ida_tasks, logger
from decompai_ida.events import DatabaseOpened, IdaEvent
from decompai_ida.tasks import GlobalTask


def analytics_timestamp() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _get_ida_version_sync() -> str:
    return ida_kernwin.get_kernel_version()


def _get_os_version() -> ty.Optional[str]:
    try:
        system = platform.system()
        if system == "Darwin":
            return f"macOS {platform.mac_ver()[0]}"
        elif system == "Linux":
            return f"Linux {platform.release()}"
        elif system == "Windows":
            return f"Windows {platform.release()}"
        else:
            return platform.release()
    except Exception as e:
        logger.get().warning("Could not determine OS version", exc_info=e)
        return None


@functools.cache
def _build_environment(
    install_id: str,
    ida_version: str,
    session_id: str,
) -> ExtraDetails:
    _OS_MAPPING = {
        "WINDOWS": OSEnum.WINDOWS,
        "DARWIN": OSEnum.MAC_OS,
        "LINUX": OSEnum.LINUX,
    }
    try:
        plugin_version = version("decompai-ida")
    except PackageNotFoundError:
        plugin_version = "unknown"

    return ExtraDetails(
        decompiler=DecompilerEnum.IDA,
        decompiler_version=ida_version,
        os_type=_OS_MAPPING.get(platform.system().upper(), OSEnum.UNKNOWN),
        os_version=_get_os_version(),
        plugin_version=plugin_version,
        install_id=install_id,
        session_id=session_id,
    )


class AnalyticsTask(GlobalTask):
    """
    Listens to IDA lifecycle and analytics events, enriches with metadata,
    and sends to backend analytics API.
    """

    def _get_environment(self) -> ExtraDetails:
        return _build_environment(
            self._ctx.install_id,
            self._ida_version,
            self._session_id,
        )

    async def _run(self) -> None:
        self._session_id = str(uuid.uuid4())
        self._ida_version = await ida_tasks.run(_get_ida_version_sync)
        api = AnalyticsApi(self._ctx.api_client)

        plugin_loaded = PluginLoadedEvent(
            timestamp=analytics_timestamp(),
            cold_start=self._ctx.is_first_install,
        )
        request = TrackEventRequest(
            event=AnalyticsEvent(actual_instance=plugin_loaded),
            environment=self._get_environment(),
        )
        await self._send_event(api, request)

        async with anyio.create_task_group() as tg:
            tg.start_soon(self._process_ida_events, tg, api)
            tg.start_soon(self._process_analytics_events, tg, api)

    async def _process_ida_events(
        self,
        tg: anyio.abc.TaskGroup,
        api: AnalyticsApi,
    ) -> None:
        async with self._ctx.ida_events.subscribe() as receiver:
            async for event in receiver:
                try:
                    client_event = await self._transform_ida_event(event)
                    if client_event is None:
                        continue
                    environment = self._get_environment()
                    request = TrackEventRequest(
                        event=AnalyticsEvent(actual_instance=client_event),
                        environment=environment,
                    )
                    tg.start_soon(self._send_event, api, request)
                except Exception as e:
                    await logger.awarning(
                        "Failed to process IDA analytics event", exc_info=e
                    )

    async def _transform_ida_event(
        self,
        event: IdaEvent,
    ) -> ty.Optional[DatabaseOpenedEvent]:
        if isinstance(event, DatabaseOpened):
            self._session_id = str(uuid.uuid4())
            return DatabaseOpenedEvent(
                timestamp=analytics_timestamp(),
                file_name=(
                    await ida_tasks.run(binary.get_binary_path_sync)
                ).name,
                file_size=await ida_tasks.run(binary.get_size_sync),
            )
        return None

    async def _process_analytics_events(
        self,
        tg: anyio.abc.TaskGroup,
        api: AnalyticsApi,
    ) -> None:
        async with self._ctx.analytics_events.subscribe() as receiver:
            async for event in receiver:
                try:
                    request = TrackEventRequest(
                        event=AnalyticsEvent(actual_instance=event),
                        environment=self._get_environment(),
                    )
                    tg.start_soon(self._send_event, api, request)
                except Exception as e:
                    await logger.awarning(
                        "Failed to process analytics event", exc_info=e
                    )

    async def _send_event(
        self, api: AnalyticsApi, request: TrackEventRequest
    ) -> None:
        """Send analytics event fire-and-forget, logging errors."""
        if self._ctx.disable_analytics:
            return
        event_type = (
            request.event.actual_instance.event_type
            if request.event.actual_instance
            else "unknown"
        )
        try:
            logger.get().debug(
                "Send AnalyticsEvent",
                event_type=event_type,
                properties=request.event.to_dict(),
            )
            await api.track_event(request)
        except Exception as e:
            await logger.awarning(
                "Failed to send analytics event",
                event_type=event_type,
                exc_info=e,
            )
