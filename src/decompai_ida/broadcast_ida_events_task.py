import ida_hexrays
import ida_idp
import ida_kernwin
import ida_typeinf
from idaapi import BADADDR

from decompai_ida import binary, ida_tasks
from decompai_ida.async_utils import (
    wait_until_cancelled,
)
from decompai_ida.broadcast import Broadcast
from decompai_ida.events import (
    AddressModified,
    AddressModifiedReason,
    DatabaseClosed,
    DatabaseOpened,
    IdaEvent,
    InitialAutoAnalysisComplete,
    LocalTypeChanged,
    MainUiReady,
    should_block_ida_events,
)
from decompai_ida.ida_tasks import AsyncCallback
from decompai_ida.model import Model
from decompai_ida.tasks import GlobalTask, Task


class BroadcastIdaEventsTask(GlobalTask):
    async def _run(self):
        was_database_open = await ida_tasks.run(binary.is_idb_open_sync)

        async with ida_tasks.install_hooks(_UiEventHooks(self._ctx.ida_events)):
            if was_database_open:
                await self._ctx.ida_events.post(DatabaseOpened())

            await wait_until_cancelled()


# Note that HexRays must not be hooked while no binary is opened.
class BroadcastHexRaysEventsTask(Task):
    async def _run(self):
        address_mask = _AddressMask()
        async with (
            ida_tasks.install_hooks(
                _HexRaysHooks(
                    self._ctx.ida_events, address_mask, self._ctx.model
                )
            ),
            ida_tasks.install_hooks(
                _DbEventHooks(
                    self._ctx.ida_events, address_mask, self._ctx.model
                )
            ),
        ):
            await wait_until_cancelled()


class _AddressMask:
    def __init__(self) -> None:
        self._masked_range = range(0, 0)

    def set_mask_on_address(self, from_address: int, to_address: int):
        self._masked_range = range(from_address, to_address)

    def stop_masking(self):
        self._masked_range = range(0, 0)

    def is_masked(self, address: int):
        return address in self._masked_range


class _BaseHooks:
    def __init__(self, broadcast: Broadcast[IdaEvent]):
        super().__init__()
        self._broadcast = broadcast
        self._queue_event_cb = AsyncCallback(self._broadcast.post)

    def _queue_event(self, event: IdaEvent):
        self._queue_event_cb(event)


class _BaseDbHooks(_BaseHooks):
    def __init__(
        self,
        broadcast: Broadcast[IdaEvent],
        address_mask: _AddressMask,
        model: Model,
    ):
        super().__init__(broadcast)
        self._model = model
        self._address_mask = address_mask

    def _report_address_modified(
        self, reason: AddressModifiedReason, address: int
    ):
        assert isinstance(address, int), f"Got: {address}"

        if not should_block_ida_events() and not self._address_mask.is_masked(
            address
        ):
            self._queue_event(AddressModified(address=address, reason=reason))


class _UiEventHooks(_BaseHooks, ida_kernwin.UI_Hooks):
    def database_inited(self, is_new_database, idc_script, /):
        self._queue_event(DatabaseOpened())
        return super().database_inited(is_new_database, idc_script)

    def database_closed(self, /):
        self._queue_event(DatabaseClosed())
        return super().database_closed()

    def ready_to_run(self, /):
        self._queue_event(MainUiReady())
        return super().ready_to_run()


class _DbEventHooks(_BaseDbHooks, ida_idp.IDB_Hooks):
    def auto_empty_finally(self, /):
        self._queue_event(InitialAutoAnalysisComplete())
        return super().auto_empty_finally()

    # Note - func_update not handled, it creates a lot of false-positive
    # updates, while other events cover the cases we care about.

    # TODO
    # def func_deleted(self, func_ea, /):

    def func_added(self, pfn, /):
        self._report_address_modified("func_added", pfn.start_ea)
        return super().func_added(pfn)

    def func_tail_appended(self, pfn, tail, /):
        self._report_address_modified("func_tail_appended", pfn.start_ea)
        return super().func_tail_appended(pfn, tail)

    def func_tail_deleted(self, pfn, tail_ea, /):
        self._report_address_modified("func_tail_deleted", pfn.start_ea)
        return super().func_tail_deleted(pfn, tail_ea)

    def tail_owner_changed(self, tail, owner_func, old_owner, /):
        self._report_address_modified("tail_owner_changed", owner_func)
        self._report_address_modified("tail_owner_changed", old_owner)
        return super().tail_owner_changed(tail, owner_func, old_owner)

    def func_noret_changed(self, pfn, /):
        self._report_address_modified("func_noret_changed", pfn.start_ea)
        return super().func_noret_changed(pfn)

    def thunk_func_created(self, pfn, /):
        self._report_address_modified("thunk_func_created", pfn.start_ea)
        return super().thunk_func_created(pfn)

    def callee_addr_changed(self, ea, callee, /):
        self._report_address_modified("callee_addr_changed", ea)
        return super().callee_addr_changed(ea, callee)

    def ti_changed(self, ea, type, fnames, /):
        self._report_address_modified("ti_changed", ea)
        return super().ti_changed(ea, type, fnames)

    def op_ti_changed(self, ea, n, type, fnames, /):
        self._report_address_modified("op_ti_changed", ea)
        return super().op_ti_changed(ea, n, type, fnames)

    def op_type_changed(self, ea, n, /):
        self._report_address_modified("op_type_changed", ea)
        return super().op_type_changed(ea, n)

    def renamed(self, ea, new_name, local_name, old_name, /):
        self._report_address_modified("renamed", ea)
        return super().renamed(ea, new_name, local_name, old_name)

    def cmt_changed(self, ea, repeatable_cmt, /):
        self._report_address_modified("cmt_changed", ea)
        return super().cmt_changed(ea, repeatable_cmt)

    def extra_cmt_changed(self, ea, line_idx, cmt, /):
        self._report_address_modified("extra_cmt_changed", ea)
        return super().extra_cmt_changed(ea, line_idx, cmt)

    def range_cmt_changed(self, kind, a, cmt, repeatable, /):
        self._report_address_modified("range_cmt_changed", a.start_ea)
        return super().range_cmt_changed(kind, a, cmt, repeatable)

    def local_types_changed(self, ltc, ordinal, name, /):
        self._queue_local_type_changed_for_ordinal(ordinal)
        return super().local_types_changed(ltc, ordinal, name)

    def _queue_local_type_changed_for_ordinal(self, ordinal: int):
        if ordinal == 0:
            return

        type_info = ida_typeinf.tinfo_t()
        success = type_info.get_numbered_type(None, ordinal)  # type: ignore
        if not success:
            return

        tid = type_info.force_tid()
        if tid == BADADDR:
            return

        self._queue_event(LocalTypeChanged(tid=tid))


class _HexRaysHooks(_BaseDbHooks, ida_hexrays.Hexrays_Hooks):
    def prolog(self, mba, fc, reachable_blocks, decomp_flags, /) -> "int":
        # This event is emitted at the beginning of decompilation, we want to
        # ignore changes made by decompiler
        self._address_mask.set_mask_on_address(
            fc.bounds.start_ea, fc.bounds.end_ea
        )
        return super().prolog(mba, fc, reachable_blocks, decomp_flags)

    def maturity(self, cfunc, new_maturity, /) -> "int":
        if new_maturity == ida_hexrays.CMAT_FINAL:
            # This is the last event while decompiling function.
            self._address_mask.stop_masking()
        return super().maturity(cfunc, new_maturity)

    def cmt_changed(self, cfunc, loc, cmt, /) -> "int":
        self._report_address_modified("pseudocode_cmt_changed", cfunc.entry_ea)
        return super().cmt_changed(cfunc, loc, cmt)

    def lvar_cmt_changed(self, vu, v, cmt, /) -> "int":
        self._report_address_modified("lvar_cmt_changed", v.defea)
        return super().lvar_cmt_changed(vu, v, cmt)

    def lvar_mapping_changed(self, vu, frm, to, /) -> "int":
        self._report_address_modified("lvar_mapping_changed", frm.defea)
        self._report_address_modified("lvar_mapping_changed", to.defea)
        return super().lvar_mapping_changed(vu, frm, to)

    def lvar_name_changed(self, vu, v, name, is_user_name, /) -> "int":
        self._report_address_modified("lvar_name_changed", v.defea)
        return super().lvar_name_changed(vu, v, name, is_user_name)

    def lvar_type_changed(self, vu, v, tinfo, /) -> "int":
        self._report_address_modified("lvar_type_changed", v.defea)
        return super().lvar_type_changed(vu, v, tinfo)
