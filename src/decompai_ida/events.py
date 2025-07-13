import typing as ty
from contextlib import contextmanager
from dataclasses import dataclass

import typing_extensions as tye

from decompai_ida.broadcast import Recorder, RecordLatestOfEachType

AddressModifiedReason = ty.Literal[
    "func_added",
    "func_tail_appended",
    "func_tail_deleted",
    "tail_owner_changed",
    "tail_owner_changed",
    "func_noret_changed",
    "thunk_func_created",
    "callee_addr_changed",
    "ti_changed",
    "op_ti_changed",
    "op_type_changed",
    "renamed",
    "cmt_changed",
    "extra_cmt_changed",
    "range_cmt_changed",
    "pseudocode_cmt_changed",
    "lvar_cmt_changed",
    "lvar_mapping_changed",
    "lvar_mapping_changed",
    "lvar_name_changed",
    "lvar_type_changed",
]


@dataclass(frozen=True)
class DatabaseOpened:
    pass


@dataclass(frozen=True)
class DatabaseClosed:
    pass


@dataclass(frozen=True)
class MainUiReady:
    pass


@dataclass(frozen=True)
class AddressModified:
    """
    Address was modified in some way (comment, name, type, etc.)

    This doesn't cover removal events (e.g. function removal).
    """

    address: int
    reason: AddressModifiedReason


@dataclass(frozen=True)
class LocalTypeChanged:
    tid: int


@dataclass(frozen=True)
class InitialAutoAnalysisComplete:
    pass


IdaEvent: tye.TypeAlias = ty.Union[
    DatabaseOpened,
    DatabaseClosed,
    MainUiReady,
    AddressModified,
    LocalTypeChanged,
    InitialAutoAnalysisComplete,
]


class EventRecorder(Recorder):
    """
    Records last event of each type, but drops all events when DB closes.
    """

    def __init__(self) -> None:
        self._inner = RecordLatestOfEachType[IdaEvent]()

    def record(self, message: IdaEvent):
        if isinstance(message, DatabaseClosed):
            self._inner.clear()
        else:
            self._inner.record(message)

    def get_recorded(self) -> ty.Iterable[IdaEvent]:
        return self._inner.get_recorded()


_ida_events_block_counter = 0


@contextmanager
def block_ida_events():
    global _ida_events_block_counter
    _ida_events_block_counter += 1
    try:
        yield
    finally:
        _ida_events_block_counter -= 1


def should_block_ida_events() -> bool:
    return _ida_events_block_counter > 0
