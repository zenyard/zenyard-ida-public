from dataclasses import dataclass
from inspect import cleandoc

from decompai_ida import inferences, logger, objects
from decompai_ida.object_graph import get_objects_in_approx_topo_order_sync
from decompai_ida.model import Revision, SyncStatus
from decompai_ida.tasks import ForegroundTask, TaskContext
from decompai_ida.wait_box import WaitBox

_SCANNING_WAITBOX_TEXT = cleandoc("""
    Zenyard is Preparing

    Scanning database
""")

_QUEUEING_WAITBOX_TEXT = cleandoc("""
    Zenyard is preparing your data for analysis — this may take a little while (<PROGRESS>)

    Once it's done, Zenyard will keep working its magic in the background and let you know as soon as your results are ready.
""")


class QueueRevisionsTask(ForegroundTask):
    """
    Foreground task which scans database for changed objects and pushes them
    into revision queue in topological order.

    Updates sync status and initial analysis status accordingly.
    """

    def __init__(self, task_context: TaskContext, wait_box: WaitBox):
        super().__init__(task_context, wait_box)
        self._buffer = list["_BufferedObject"]()

    def _run(self):
        self._is_initial_upload = not (
            self._ctx.model.initial_upload_complete.get_sync()
        )

        self._wait_box.start_new_task(_SCANNING_WAITBOX_TEXT)

        dirty_addresses = get_objects_in_approx_topo_order_sync(
            self._find_dirty_symbols()
        )
        logger.debug(
            "Scanned for dirty addresses", dirty_count=len(dirty_addresses)
        )

        self._wait_box.start_new_task(
            _QUEUEING_WAITBOX_TEXT,
            items=len(dirty_addresses),
        )

        for address in dirty_addresses:
            self._buffer_object_if_changed(address)
            if (
                len(self._buffer)
                == self._ctx.static_config.max_objects_in_revision
            ):
                self._flush_revision()
            self._wait_box.mark_items_complete(1)

        if len(self._buffer) > 0:
            self._flush_revision()

        self._ctx.model.database_dirty.set_sync(False)
        if self._is_initial_upload:
            self._ctx.model.initial_upload_complete.set_sync(True)
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
            Revision(
                objects=tuple(
                    buffered_object.object for buffered_object in self._buffer
                ),
                is_initial_analysis=self._is_initial_upload,
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

    def _find_dirty_symbols(self):
        for symbol in objects.all_object_symbols_sync():
            sync_status = (
                self._ctx.model.sync_status.get_sync(symbol.address)
            ) or SyncStatus()
            if sync_status.dirty:
                yield symbol


@dataclass
class _BufferedObject:
    address: int
    object: objects.Object
    hash: bytes
