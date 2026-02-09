import typing as ty
from abc import abstractmethod
from dataclasses import dataclass
from inspect import cleandoc

from decompai_ida import ida_tasks, inferences, logger, objects
from decompai_ida.object_graph import get_objects_in_approx_topo_order_sync
from decompai_ida.model import Object, Revision, SyncStatus
from decompai_ida.objects import Symbol
from decompai_ida.tasks import ForegroundTask

_SCANNING_WAITBOX_TEXT = cleandoc("""
    Zenyard is Preparing

    Scanning database
""")

_QUEUEING_WAITBOX_TEXT = cleandoc("""
    Zenyard is preparing your data for analysis — this may take a little while (<PROGRESS>)

    Once it's done, Zenyard will keep working its magic in the background and let you know as soon as your results are ready.
""")


@dataclass
class _BufferedObject:
    address: int
    object: Object
    hash: bytes


class BaseQueueRevisionsTask(ForegroundTask):
    """
    Base class for foreground tasks that scan objects and push them into the
    revision queue in topological order.
    """

    def _run(self) -> None:
        self._buffer = list[_BufferedObject]()

        self._wait_box.start_new_task(_SCANNING_WAITBOX_TEXT)

        addresses = get_objects_in_approx_topo_order_sync(
            self._get_symbols_to_queue()
        )
        logger.debug("Scanned for addresses to queue", count=len(addresses))

        self._wait_box.start_new_task(
            _QUEUEING_WAITBOX_TEXT,
            items=len(addresses),
        )

        for address in addresses:
            self._buffer_object_if_changed(address)
            if (
                len(self._buffer)
                == self._ctx.static_config.max_objects_in_revision
            ):
                self._flush_revision()
            self._wait_box.mark_items_complete(1)
            ida_tasks.execute_queued_tasks_sync()

        if len(self._buffer) > 0:
            self._flush_revision()

        self._ctx.model.notify_update()

    def _buffer_object_if_changed(self, address: int) -> None:
        log = logger.bind(address=address)

        sync_status = (
            self._ctx.model.sync_status.get_sync(address)
        ) or SyncStatus()

        # Ensure all pending inferences are applied before reading.
        inferences.apply_pending_inferences_sync(address, model=self._ctx.model)

        try:
            obj = objects.read_object_sync(address, model=self._ctx.model)
        except Exception as ex:
            log.warning("Can't read object", exc_info=ex)
            # Mark clean so we don't try this again until next change.
            self._ctx.model.sync_status.set_sync(
                address, sync_status.with_dirty(False)
            )
            return

        current_hash = objects.hash_object(obj)
        if current_hash == sync_status.uploaded_hash:
            log.debug("Object unchanged")
            self._ctx.model.sync_status.set_sync(
                address, sync_status.with_dirty(False)
            )

        self._buffer.append(
            _BufferedObject(address=address, object=obj, hash=current_hash)
        )
        log.debug("Object buffered for revision")

    def _flush_revision(self) -> None:
        assert (
            0
            < len(self._buffer)
            <= self._ctx.static_config.max_objects_in_revision
        )

        logger.info("Queueing revision", object_count=len(self._buffer))

        self._ctx.model.revision_queue.push_sync(
            self._create_revision(
                tuple(
                    buffered_object.object for buffered_object in self._buffer
                )
            )
        )

        # Mark all objects uploaded and clean.
        for buffered_object in self._buffer:
            self._ctx.model.sync_status.set_sync(
                buffered_object.address,
                SyncStatus(uploaded_hash=buffered_object.hash, dirty=False),
            )
            logger.debug("Object marked clean", address=buffered_object.address)

        self._buffer.clear()
        self._ctx.model.notify_update()

    @abstractmethod
    def _get_symbols_to_queue(self) -> ty.Iterable[Symbol]: ...

    @abstractmethod
    def _create_revision(self, objects: tuple[Object, ...]) -> Revision: ...


class QueueRevisionsTask(BaseQueueRevisionsTask):
    """
    Foreground task which scans database for changed objects and pushes them
    into revision queue in topological order.

    Updates sync status and initial analysis status accordingly.
    """

    def _run(self) -> None:
        self._is_initial_upload = not (
            self._ctx.model.initial_upload_complete.get_sync()
        )

        super()._run()

        self._ctx.model.database_dirty.set_sync(False)
        if self._is_initial_upload:
            self._ctx.model.initial_upload_complete.set_sync(True)
        self._ctx.model.notify_update()

    def _get_symbols_to_queue(self) -> ty.Iterable[Symbol]:
        for symbol in objects.all_object_symbols_sync():
            sync_status = (
                self._ctx.model.sync_status.get_sync(symbol.address)
            ) or SyncStatus()
            if sync_status.dirty:
                yield symbol

    def _create_revision(self, objects: tuple[Object, ...]) -> Revision:
        return Revision(
            objects=objects, is_initial_analysis=self._is_initial_upload
        )
