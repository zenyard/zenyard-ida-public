import typing as ty

import typing_extensions as tye

from decompai_ida.model import Object, Revision
from decompai_ida.objects import Symbol
from decompai_ida.queue_revisions_task import BaseQueueRevisionsTask


class QueueSwiftRevisionsTask(BaseQueueRevisionsTask):
    """
    Foreground task that creates swift-only revisions for specific addresses.
    """

    def __init__(self, addresses: ty.Iterable[int]):
        self._addresses = set(addresses)

    def merge_from(self, other: tye.Self) -> None:
        self._addresses |= other._addresses

    def _get_symbols_to_queue(self) -> ty.Iterable[Symbol]:
        return [
            Symbol(address=addr, type="function") for addr in self._addresses
        ]

    def _create_revision(self, objects: tuple[Object, ...]) -> Revision:
        return Revision(
            objects=objects, is_initial_analysis=True, swift_only=True
        )
