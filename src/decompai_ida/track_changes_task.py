import typing as ty

import ida_funcs
import ida_typeinf
import idautils
import structlog
from idaapi import BADADDR

from decompai_ida import ida_tasks, logger, objects
from decompai_ida.events import (
    AddressModified,
    AddressModifiedReason,
    LocalTypeChanged,
)
from decompai_ida.tasks import Task

# When non-object address is changed by one of these reasons, propagate change to
# referencing objects.
_PROPAGATE_NON_OBJECT_CHANGE_ON_REASONS: set[AddressModifiedReason] = {
    "func_added",
    "func_noret_changed",
    "thunk_func_created",
    "ti_changed",
    "renamed",
}

# Ignore the following when they occur within object bounds, but not at its
# beginning.
_IGNORE_IN_MID_OBJECT: set[AddressModifiedReason] = {
    # Non pseudocode comments don't show up in decompiled output unless they
    # at the function entry.
    "cmt_changed",
    "extra_cmt_changed",
    "range_cmt_changed",
}


class TrackChangesTask(Task):
    async def _run(self):
        await logger.adebug("Waiting for auto analysis")
        await self._ctx.model.wait_for_initial_analysis()

        await logger.adebug("Start reacting to events")
        async with self._ctx.ida_events.subscribe(
            replay_recorded=False
        ) as event_receiver:
            async for event in event_receiver:
                if not self._ctx.model.runtime_status.ida_settled:
                    await logger.adebug(
                        "Ignoring event while IDA is unsettled",
                        event_type=type(event).__name__,
                    )
                    continue

                if isinstance(event, AddressModified):
                    await logger.adebug(
                        "Got address modified", address=event.address
                    )
                    await ida_tasks.run(
                        self._handle_address_changed_sync, event
                    )
                elif isinstance(event, LocalTypeChanged):
                    await logger.adebug("Got local type changed", tid=event.tid)
                    await ida_tasks.run(
                        self._handle_local_type_changed_sync, event
                    )

    def _handle_address_changed_sync(self, event: AddressModified):
        with structlog.contextvars.bound_contextvars(
            changed_address=event.address, reason=event.reason
        ):
            any_address_changed = False
            for address in self._extract_changed_object_addresses(event):
                self._mark_object_dirty(address)
                any_address_changed = True

            if any_address_changed:
                self._ctx.model.database_dirty.set_sync(True)
                self._ctx.model.notify_update()

    def _handle_local_type_changed_sync(self, event: LocalTypeChanged):
        with structlog.contextvars.bound_contextvars(tid=event.tid):
            all_affected_objects = {
                obj
                for obj in self._ctx.model.tid_to_object.get_by_left_sync(
                    event.tid
                )
            }

            for obj in all_affected_objects:
                logger.debug(
                    "Object changed indirectly from type",
                    address=obj,
                )
                self._mark_object_dirty(obj)

            if len(all_affected_objects) > 0:
                self._ctx.model.database_dirty.set_sync(True)
                self._ctx.model.notify_update()

    def _mark_object_dirty(self, address: int):
        sync_status = self._ctx.model.sync_status.get_sync(address)
        if sync_status is not None and not sync_status.dirty:
            self._ctx.model.sync_status.set_sync(
                address, sync_status.with_dirty(True)
            )

    # TODO: Currently global variable inferences will cause tracked changes in referenced
    # functions, this is on purpose to allow re-inferencing of functions it is used in.
    def _extract_changed_object_addresses(
        self,
        event: AddressModified,
    ) -> ty.Iterator[int]:
        object_address = _get_object_address(event.address)
        if object_address is not None:
            if (
                event.address != object_address
                and event.reason in _IGNORE_IN_MID_OBJECT
            ):
                logger.debug(
                    "Ignoring event in mid-object",
                    object_address=object_address,
                )

            else:
                logger.debug("Object changed directly")
                yield object_address

        elif (
            event.reason in _PROPAGATE_NON_OBJECT_CHANGE_ON_REASONS
            # Avoid propagating changes from ignored segments.
            and not objects.is_in_ignored_segment_sync(event.address)
        ):
            # Any referencing object may have changed.
            for referencing_address in (
                *idautils.DataRefsTo(event.address),
                *idautils.CodeRefsTo(event.address, flow=False),
            ):
                referencing_address = _get_object_address(referencing_address)
                if referencing_address is not None:
                    logger.debug(
                        "Object changed indirectly",
                        address=referencing_address,
                    )
                    yield referencing_address


def _get_object_address(address: int) -> ty.Optional[int]:
    # Skip ignored segments
    if objects.is_in_ignored_segment_sync(address):
        return None

    # Skip non functions
    func = ida_funcs.get_func(address)
    if func is None:
        return None

    # Object address is function entry point.
    return func.start_ea


def _directly_referencing_tids(tid: int) -> ty.Iterable[int]:
    "Get types directly referencing given type"
    type_info = ida_typeinf.tinfo_t()
    for referencing_address in idautils.DataRefsTo(tid):
        referencing_ordinal = ida_typeinf.get_tid_ordinal(referencing_address)
        if referencing_ordinal == 0:
            continue

        # Note that referencing address may be an offset within a type, we want
        # base tid.
        success = type_info.get_numbered_type(None, referencing_ordinal)  # type: ignore
        if not success:
            continue

        tid = type_info.force_tid()
        if tid != BADADDR:
            yield tid
