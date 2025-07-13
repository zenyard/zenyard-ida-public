import typing as ty

import anyio
from anyio.abc import ObjectReceiveStream

_T = ty.TypeVar("_T")


async def wait_for_object_of_type(
    receiver: ObjectReceiveStream[_T], *type_: type[_T]
) -> ty.Optional[_T]:
    async for item in receiver:
        if isinstance(item, type_):
            return item


async def collect(async_iterable: ty.AsyncIterable[_T]) -> list[_T]:
    return [item async for item in async_iterable]


async def consume(async_iterable: ty.AsyncIterable[None]):
    async for _ in async_iterable:
        pass


async def wait_until_cancelled():
    await anyio.Event().wait()
