"""
Utilities to persist data into IDB.

All instances must only be used from IDA's thread.
"""

import typing as ty

import ida_netnode
import msgpack
import pydantic

from decompai_ida import ida_tasks

_T = ty.TypeVar("_T")

_NAME_PREFIX = "$ decompai."
_ARRAYS = 4


class _NotSet:
    pass


class SingleValue(ty.Generic[_T]):
    def __init__(self, name: str, type_: ty.Any, *, default: _T):
        self._storage = _Storage(name, type_, scale=0x1000_0000)
        self._default = default
        self._cache: ty.Union[_T, _NotSet] = _NotSet()

    def get_sync(self) -> ty.Any:
        if isinstance(self._cache, _NotSet):
            self._cache = self._storage.get(0, default=self._default)
        return self._cache

    async def get(self) -> _T:
        # Avoid queueing task if cached.
        if not isinstance(self._cache, _NotSet):
            return self._cache
        return await ida_tasks.run(self.get_sync)

    def set_sync(self, value: ty.Any) -> None:
        self._storage.set(0, value)
        self._cache = value

    async def set(self, value: ty.Any) -> None:
        return await ida_tasks.run(self.set_sync, value)

    def clear_sync(self) -> None:
        self._storage.clear()

    async def clear(self) -> None:
        return await ida_tasks.run(self.clear_sync)


class AddressMap(ty.Generic[_T]):
    def __init__(self, name: str, type_: type[_T]):
        self._storage = _Storage(name, type_, scale=1)

    def get_sync(self, address: int) -> ty.Optional[_T]:
        return self._storage.get(address)

    async def get(self, address: int) -> ty.Optional[_T]:
        return await ida_tasks.run(self.get_sync, address)

    def set_sync(self, address: int, value: ty.Optional[_T]) -> None:
        self._storage.set(address, value)

    async def set(self, address: int, value: ty.Optional[_T]) -> None:
        return await ida_tasks.run(self.set_sync, address, value)

    def clear_sync(self) -> None:
        self._storage.clear()

    async def clear(self) -> None:
        return await ida_tasks.run(self.clear_sync)


class Queue(ty.Generic[_T]):
    def __init__(self, name: str, type_: ty.Any):
        self._state_storage = SingleValue(
            f"{name}.state", _QueueState, default=_QueueState()
        )
        self._queue_storage = _Storage(name, type_, scale=0x10000)

    def size_sync(self) -> int:
        state = self._state_storage.get_sync()
        return state.size

    async def size(self) -> int:
        return await ida_tasks.run(self.size_sync)

    def peek_sync(self, count: int = 1) -> ty.Sequence[ty.Optional[_T]]:
        state = self._state_storage.get_sync()
        return [
            self._queue_storage.get(i)
            for i in range(
                state.start_index,
                min(state.start_index + count, state.end_index),
            )
        ]

    async def peek(self, count: int = 1) -> ty.Sequence[ty.Optional[_T]]:
        return await ida_tasks.run(self.peek_sync, count)

    def pop_sync(self, count: int = 1) -> None:
        state = self._state_storage.get_sync()
        new_start_index = min(state.start_index + count, state.end_index)
        deleted_range = range(state.start_index, new_start_index)

        if new_start_index < state.end_index:
            state.start_index = new_start_index
        else:
            state = _QueueState()
        self._state_storage.set_sync(state)

        for i in deleted_range:
            self._queue_storage.set(i, None)

    async def pop(self, count: int = 1) -> None:
        return await ida_tasks.run(self.pop_sync, count)

    def push_sync(self, value: _T) -> None:
        state = self._state_storage.get_sync()
        self._queue_storage.set(state.end_index, value)
        state.end_index += 1
        self._state_storage.set_sync(state)

    async def push(self, value: _T) -> None:
        return await ida_tasks.run(self.push_sync, value)

    def clear_sync(self) -> None:
        self._state_storage.clear_sync()
        self._queue_storage.clear()

    async def clear(self) -> None:
        return await ida_tasks.run(self.clear_sync)


class AddressMultiMap(ty.Generic[_T]):
    """
    Stores multiple values per address.
    """

    def __init__(self, name: str, type_: ty.Any, *, item_scale=0x400):
        self._index_storage = SingleValue(f"{name}.index", int, default=0)
        self._heads_storage = AddressMap(f"{name}.heads", int)
        self._items_storage = _Storage(
            f"{name}.items", _MultiMapItem[type_], scale=item_scale
        )

    def push_sync(self, address: int, value: _T) -> None:
        index = self._index_storage.get_sync()
        previous_head = self._heads_storage.get_sync(address)
        self._items_storage.set(
            index, _MultiMapItem(value=value, next_index=previous_head)
        )
        self._index_storage.set_sync(index + 1)
        self._heads_storage.set_sync(address, index)

    async def push(self, address: int, value: _T) -> None:
        return await ida_tasks.run(self.push_sync, address, value)

    def read_sync(self, address: int) -> ty.Iterable[_T]:
        index = self._heads_storage.get_sync(address)
        while index is not None:
            record = self._items_storage.get(index)
            assert record is not None
            yield record.value
            index = record.next_index

    async def remove(self, address: int, value: _T) -> None:
        return await ida_tasks.run(self.remove_sync, address, value)

    def remove_sync(self, address: int, value: _T) -> None:
        prev_index_and_value: ty.Optional[tuple[int, _T]] = None
        index = self._heads_storage.get_sync(address)
        while index is not None:
            record = self._items_storage.get(index)
            assert record is not None

            if record.value == value:
                if prev_index_and_value is not None:
                    prev_index, prev_value = prev_index_and_value
                    self._items_storage.set(
                        prev_index,
                        _MultiMapItem(
                            next_index=record.next_index,
                            value=prev_value,
                        ),
                    )
                else:
                    self._heads_storage.set_sync(address, record.next_index)
                self._items_storage.set(index, None)
                break

            prev_index_and_value = (index, record.value)
            index = record.next_index

    async def read(self, address: int) -> ty.Sequence[_T]:
        return await ida_tasks.run(lambda: list(self.read_sync(address)))

    def clear_address_sync(self, address: int):
        index = self._heads_storage.get_sync(address)
        self._heads_storage.set_sync(address, None)
        while index is not None:
            record = self._items_storage.get(index)
            assert record is not None
            self._items_storage.set(index, None)
            index = record.next_index

    async def clear_address(self, address: int):
        await ida_tasks.run(self.clear_address_sync, address)

    async def clear(self):
        await self._index_storage.clear()
        await self._heads_storage.clear()
        await ida_tasks.run(self._items_storage.clear)


class AddressRelation:
    """
    Stores pairs of addresses like `(left, right)`.

    Allows lookup by left address, and bulk replace and insert by right address.
    """

    def __init__(self, name: str) -> None:
        self._left_map = AddressMultiMap(f"{name}.left", int, item_scale=1)
        self._right_map = AddressMultiMap(f"{name}.right", int, item_scale=1)

    def get_by_left_sync(self, left: int) -> set[int]:
        """
        Get all right addresses paired with given left address.
        """
        return set(self._left_map.read_sync(left))

    def replace_by_right_sync(self, right: int, lefts: ty.Iterable[int]):
        """
        Remove all existing addresses paired with given left address, and insert
        new pairs in bulk.
        """
        prev_lefts = set(self._right_map.read_sync(right))
        lefts = set(lefts)

        for removed_left in prev_lefts - lefts:
            self._left_map.remove_sync(removed_left, right)

        for added_left in lefts - prev_lefts:
            self._left_map.push_sync(added_left, right)

        if prev_lefts != lefts:
            self._right_map.clear_address_sync(right)
            for left in lefts:
                self._right_map.push_sync(right, left)

    async def clear(self):
        await self._left_map.clear()
        await self._right_map.clear()


class _QueueState(pydantic.BaseModel):
    start_index: int = 0
    end_index: int = 0

    @property
    def size(self) -> int:
        return self.end_index - self.start_index


class _MultiMapItem(pydantic.BaseModel, ty.Generic[_T]):
    value: _T
    next_index: ty.Optional[int]


class _Storage(ty.Generic[_T]):
    """
    Stores Pydantic models in netnode, keyed by integers.

    Note that IDA's blob storage will use consecutive keys when value is larger
    than 1024. This is handled by spreading keys over different arrays, and by
    scaling keys. So the maximum value size is `1024 * _ARRAYS * scale`, and the
    maximum key is `2^64 / scale`. Maximum size is enforced to avoid corruption.
    """

    def __init__(self, name: str, type_: type[_T], *, scale: int):
        self._full_name = _NAME_PREFIX + name
        self._node = ida_netnode.netnode(self._full_name, 0, True)
        self._type_adapter = pydantic.TypeAdapter(type_)
        self._scale = scale

    def clear(self) -> None:
        self._node.kill()
        self._node = ida_netnode.netnode(self._full_name, 0, True)

    @ty.overload
    def get(self, index: int) -> ty.Optional[_T]: ...

    @ty.overload
    def get(self, index: int, *, default: _T) -> _T: ...

    def get(
        self, index: int, *, default: ty.Optional[_T] = None
    ) -> ty.Optional[_T]:
        scaled_index, array = self._get_scaled_index_and_array(index)
        serialized = self._node.getblob(scaled_index, array)
        if serialized is None:
            return default
        try:
            return self._type_adapter.validate_python(
                msgpack.unpackb(serialized)
            )
        except Exception:
            return default

    def set(self, index: int, value: ty.Optional[_T]):
        scaled_index, array = self._get_scaled_index_and_array(index)
        if value is not None:
            serialized = msgpack.packb(
                self._type_adapter.dump_python(value, mode="json")
            )
            assert serialized is not None
            self._check_blob_size(serialized)
            self._node.setblob(serialized, scaled_index, array)
        else:
            self._node.delblob(scaled_index, array)

    def _get_scaled_index_and_array(self, index) -> tuple[int, int]:
        scaled_index = index * self._scale
        array = scaled_index % _ARRAYS
        if scaled_index * self._scale >= 2**64:
            raise ValueError(f"Index out of bounds: {index}")
        return scaled_index, array

    def _check_blob_size(self, blob: bytes):
        if len(blob) > ida_netnode.MAXSPECSIZE * _ARRAYS * self._scale:
            raise ValueError("Value too large for storage")
