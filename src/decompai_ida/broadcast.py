import threading
import typing as ty
from abc import abstractmethod
from collections import OrderedDict, deque

import anyio
from anyio.abc import AsyncResource, ObjectReceiveStream, ObjectSendStream

_T = ty.TypeVar("_T")


class Recorder(ty.Protocol, ty.Generic[_T]):
    @abstractmethod
    def record(self, message: _T): ...

    @abstractmethod
    def get_recorded(self) -> ty.Iterable[_T]: ...


class RecordNone(Recorder, ty.Generic[_T]):
    def record(self, message: _T):
        pass

    def get_recorded(self) -> ty.Iterable[_T]:
        return ()


class RecordLatest(Recorder, ty.Generic[_T]):
    """
    Only hold one latest message, similar to Tokio `watch_channel`.
    """

    _recorded: ty.Union[tuple[()], tuple[_T]] = ()

    def record(self, message: _T):
        self._recorded = (message,)

    def get_recorded(self) -> ty.Iterable[_T]:
        return self._recorded


class RecordLatestN(Recorder, ty.Generic[_T]):
    """
    Hold up to n latest messages, dropping older ones.
    """

    _recorded: deque[_T]

    def __init__(self, n: int) -> None:
        self._recorded = deque(maxlen=n)

    def record(self, message: _T):
        self._recorded.append(message)

    def get_recorded(self) -> ty.Iterable[_T]:
        return list(self._recorded)


class RecordLatestOfEachType(Recorder, ty.Generic[_T]):
    """
    Only hold latest message of each subtype. Recorded messages are replayed in
    order of arrival.
    """

    _recorded: OrderedDict[type[_T], _T]

    def __init__(self) -> None:
        self._recorded = OrderedDict()

    def record(self, message: _T):
        if type(message) in self._recorded:
            del self._recorded[type(message)]

        self._recorded[type(message)] = message

    def get_recorded(self) -> ty.Iterable[_T]:
        return self._recorded.values()

    def clear(self):
        self._recorded.clear()


class Broadcast(AsyncResource, ty.Generic[_T]):
    """
    A broadcast channel on top of anyio object stream.

    Optionally allows recording messages for future subscribers.
    """

    _subscribers_lock: threading.Lock
    _subscribers: set[ObjectSendStream[_T]]
    _recorder: Recorder[_T]

    def __init__(self, recoder: Recorder[_T] = RecordNone()) -> None:
        """
        `recorder` allows controlling how messages are recorded for future
        subscribers.
        """
        self._subscribers_lock = threading.Lock()
        self._subscribers = set()
        self._recoder = recoder

    async def post(self, message: _T):
        """
        Send message to current subscribers.

        Returns when message is queued to all subscribers.
        """
        with self._subscribers_lock:
            subscribers = self._subscribers.copy()
            self._recoder.record(message)

        to_remove: set[ObjectSendStream[_T]] = set()
        for subscriber in subscribers:
            try:
                await subscriber.send(message)
            except anyio.BrokenResourceError:
                # Subscriber stream is closed
                to_remove.add(subscriber)

        if len(to_remove) > 0:
            with self._subscribers_lock:
                self._subscribers -= to_remove

    def subscribe(
        self,
        buffer_size: float = 128,
        replay_recorded: bool = True,
    ) -> ObjectReceiveStream[_T]:
        """
        Start receiving broadcasts to a new receiver channel.

        When `replay_recorded` is True, recorded messages will be pushed to
        stream before subscribing. Stream must have buffer capacity for holding
        the recorded messages, otherwise this raises.
        """
        send_stream, receive_stream = anyio.create_memory_object_stream(
            buffer_size
        )

        with self._subscribers_lock:
            self._subscribers.add(send_stream)
            if replay_recorded:
                for recorded_message in self._recoder.get_recorded():
                    send_stream.send_nowait(recorded_message)

        return receive_stream

    async def aclose(self):
        "Unsubscribe all"

        with self._subscribers_lock:
            subscribers = self._subscribers.copy()
            self._subscribers.clear()

        for subscriber in subscribers:
            await subscriber.aclose()
