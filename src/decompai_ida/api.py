import typing as ty
from asyncio.exceptions import TimeoutError
from contextlib import asynccontextmanager

from aiohttp.client_exceptions import ClientConnectionError

from decompai_client import ApiClient
from decompai_client import (
    Configuration as ApiConfiguration,
)
from decompai_client.exceptions import ServiceException
from decompai_ida import configuration, ida_tasks


@asynccontextmanager
async def open_api_client() -> ty.AsyncIterator[ApiClient]:
    plugin_config = await ida_tasks.run(configuration.read_configuration_sync)

    client_config = ApiConfiguration(
        host=str(plugin_config.api_url).rstrip("/"),
        api_key={"APIKeyHeader": plugin_config.api_key},
    )

    client_config.verify_ssl = plugin_config.verify_ssl

    async with ApiClient(client_config) as api_client:
        yield api_client


def is_temporary_error(error: Exception):
    """
    True for network and server side (500) errors.
    """
    return isinstance(
        error, (ClientConnectionError, ServiceException, TimeoutError)
    )


def parse_address(api_address: str) -> int:
    return int(api_address, 16)


def format_address(address: int) -> str:
    return f"{address:016x}"
