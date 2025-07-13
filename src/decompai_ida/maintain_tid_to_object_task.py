import ida_hexrays
import ida_typeinf
from idaapi import BADADDR

from decompai_ida import ida_tasks, objects
from decompai_ida.async_utils import wait_until_cancelled
from decompai_ida.model import Model
from decompai_ida.tasks import Task


class MaintainTidToObjectTask(Task):
    async def _run(self) -> None:
        async with ida_tasks.install_hooks(
            _MaintainTidToObjectHooks(self._ctx.model)
        ):
            await wait_until_cancelled()


class _MaintainTidToObjectHooks(ida_hexrays.Hexrays_Hooks):
    def __init__(self, model: Model):
        super().__init__()
        self._model = model

    def maturity(self, cfunc, new_maturity, /) -> "int":
        if (
            new_maturity == ida_hexrays.CMAT_FINAL
            and not objects.is_in_ignored_segment_sync(cfunc.entry_ea)
        ):
            self._maintain_on_func(cfunc)

        return super().maturity(cfunc, new_maturity)

    def _maintain_on_func(self, cfunc: ida_hexrays.cfunc_t):
        type_info_tid_collector = _TypeInfoTidCollector()

        # Collect from signature
        func_type = ida_typeinf.tinfo_t()
        success = cfunc.get_func_type(func_type)
        if success:
            type_info_tid_collector.apply_to(func_type)

        # Collect from variables
        for lvar in cfunc.lvars:  # type: ignore
            # Arguments already handled as part of signature
            if not lvar.is_arg_var:
                type_info_tid_collector.apply_to(lvar.type())

        # Collect from body.
        ctree_type_info_collector = _CtreeTypeInfoCollector()
        ctree_type_info_collector.apply_to(cfunc.body, None)  # type: ignore

        for type_info in ctree_type_info_collector.collected:
            type_info_tid_collector.apply_to(type_info)

        self._model.tid_to_object.replace_by_right_sync(
            right=cfunc.entry_ea,
            lefts=type_info_tid_collector.collected,
        )


class _CtreeTypeInfoCollector(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.collected = list[ida_typeinf.tinfo_t]()

    def visit_expr(self, e):
        if not e.type.empty():
            self.collected.append(e.type)
        return 0


class _TypeInfoTidCollector(ida_typeinf.tinfo_visitor_t):
    def __init__(self):
        super().__init__(ida_typeinf.TVST_DEF)
        self.collected = set[int]()

    def visit_type(self, out, tif, name, cmt):
        tid = tif.force_tid()
        if tif.force_tid() != BADADDR:
            self.collected.add(tid)
        return 0
