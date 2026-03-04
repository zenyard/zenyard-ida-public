from dataclasses import dataclass
import typing as ty
from functools import cache

import ida_bytes
import ida_hexrays
import ida_typeinf
from idaapi import BADADDR

from decompai_ida import ida_tasks
from decompai_ida.async_utils import wait_until_cancelled
from decompai_ida.tasks import Task

_DBG_INFO_SIZE = 0x1C
_PTR_SIZE = 4


class InlineShannonDebugTracesTask(Task):
    """
    Inline text from Shannon (Samsung's modem) `dbg_trace` type.
    """

    async def _run(self) -> None:
        _get_debug_trace_ptr_tinfo.cache_clear()
        _get_trace_payload_ptr_tinfo.cache_clear()
        _get_string_literal_tinfo.cache_clear()
        async with ida_tasks.install_hooks(_InlineDebugTraces()):
            await wait_until_cancelled()


@dataclass(frozen=True)
class _GlobalReference:
    node: ida_hexrays.cexpr_t
    address: int


class _FindGlobalReferencesWithType(ida_hexrays.ctree_visitor_t):
    def __init__(self, target_type: ida_typeinf.tinfo_t):
        super().__init__(ida_hexrays.CV_FAST)
        self._target_type = target_type
        self.findings = list[_GlobalReference]()

    def visit_expr(self, arg0: ida_hexrays.cexpr_t, /) -> int:
        if arg0.type != self._target_type:
            return 0

        value = _compute(_to_expr(arg0))
        if value is None:
            return 0

        self.findings.append(_GlobalReference(node=arg0, address=value))
        self.prune_now()
        return 0


class _InlineDebugTraces(ida_hexrays.Hexrays_Hooks):
    def maturity(self, cfunc: ida_hexrays.cfunc_t, new_maturity: int, /) -> int:
        if new_maturity == ida_hexrays.CMAT_FINAL:
            self._inline_debug_traces(cfunc)

        return super().maturity(cfunc, new_maturity)

    def _inline_debug_traces(self, cfunc: ida_hexrays.cfunc_t):
        debug_trace_ptr_tinfo = _get_debug_trace_ptr_tinfo()
        trace_payload_ptr_tinfo = _get_trace_payload_ptr_tinfo()

        # We test for `trace_payload` existence to be more confident we're
        # looking at Shannon firmware.
        if debug_trace_ptr_tinfo is None or trace_payload_ptr_tinfo is None:
            return

        finder = _FindGlobalReferencesWithType(debug_trace_ptr_tinfo)
        finder.apply_to(cfunc.body, None)  # type: ignore

        for finding in finder.findings:
            text = _format_debug_trace(finding.address)
            if text is None:
                continue

            str_node = ida_hexrays.cexpr_t()
            str_node.ea = BADADDR  # type: ignore
            str_node.op = ida_hexrays.cot_str  # type: ignore
            str_node.string = text
            str_node.exflags = ida_hexrays.EXFL_CSTR
            str_node.type = _get_string_literal_tinfo()

            cast_node = ida_hexrays.cexpr_t()
            cast_node.ea = finding.node.ea  # type: ignore
            cast_node.op = ida_hexrays.cot_cast  # type: ignore
            cast_node.x = str_node
            cast_node.type = debug_trace_ptr_tinfo

            finding.node.swap(cast_node)


@cache
def _get_debug_trace_ptr_tinfo() -> ty.Optional[ida_typeinf.tinfo_t]:
    tinfo = ida_typeinf.tinfo_t()
    success = tinfo.parse(
        "dbg_trace*;", ida_typeinf.get_idati(), ida_typeinf.PT_SIL
    )
    return tinfo if success else None


@cache
def _get_trace_payload_ptr_tinfo() -> ty.Optional[ida_typeinf.tinfo_t]:
    tinfo = ida_typeinf.tinfo_t()
    success = tinfo.parse(
        "trace_payload*;", ida_typeinf.get_idati(), ida_typeinf.PT_SIL
    )
    return tinfo if success else None


@cache
def _get_string_literal_tinfo() -> ida_typeinf.tinfo_t:
    tinfo = ida_typeinf.tinfo_t()
    success = tinfo.parse("char*;", ida_typeinf.get_idati(), ida_typeinf.PT_SIL)
    assert success
    return tinfo


def _format_debug_trace(address: int) -> ty.Optional[str]:
    message_ptr = ida_bytes.get_dword(address + 4 * 4)
    return _read_str(message_ptr)


def _read_str(address: int) -> ty.Optional[str]:
    raw = ida_bytes.get_bytes(address, 4096, ida_bytes.GMB_READALL)
    if raw is None:
        return
    null_or_undefined_index = next(
        (i for i, byte in enumerate(raw) if byte in (0, 0xFF)),
        len(raw),
    )
    if null_or_undefined_index == 0:
        return
    return raw[:null_or_undefined_index].decode("ascii", errors="replace")


_Expr: ty.TypeAlias = ty.Union[
    "_Unknown", "_Number", "_Address", "_AddressOf", "_Add", "_Sub", "_Index"
]


@dataclass(frozen=True)
class _Unknown:
    pass


@dataclass(frozen=True)
class _Number:
    value: int


@dataclass(frozen=True)
class _Address:
    address: int


@dataclass(frozen=True)
class _AddressOf:
    expr: _Expr


@dataclass(frozen=True)
class _Add:
    x: _Expr
    y: _Expr


@dataclass(frozen=True)
class _Sub:
    x: _Expr
    y: _Expr


@dataclass(frozen=True)
class _Index:
    base: _Expr
    index: _Expr


def _compute(expr: _Expr) -> ty.Optional[int]:
    match expr:
        case _Number(value):
            return value

        case _Index(base=_Address(base), index=index):
            # This assumes indexing only done on arrays of `dbg_trace*`.
            index = _compute(index)
            if index is None:
                return
            return _compute(_Address(base + index * _PTR_SIZE))

        case _AddressOf(_Address(address)):
            return address

        case _Address(address):
            return ida_bytes.get_dword(address)

        case _Add(_Address() as address, _Number(offset)) | _Add(
            _Number(offset), _Address() as address
        ):
            # This assumes offsetting only done on `dbg_trace*`.
            address = _compute(address)
            if address is None:
                return
            return address + offset * _DBG_INFO_SIZE

        case _Sub(_Address() as address, _Number(offset)):
            # This assumes offsetting only done on `dbg_trace*`.
            address = _compute(address)
            if address is None:
                return
            return address - offset * _DBG_INFO_SIZE

        case _:
            return


def _to_expr(node: ida_hexrays.cexpr_t) -> _Expr:
    op: int = node.op  # type: ignore

    if op == ida_hexrays.cot_obj:
        return _Address(node.obj_ea)

    if op == ida_hexrays.cot_ref:
        return _AddressOf(_to_expr(node.x))

    elif op == ida_hexrays.cot_idx:
        return _Index(base=_to_expr(node.x), index=_to_expr(node.y))

    elif op == ida_hexrays.cot_num:
        return _Number(node.n._value)

    elif op == ida_hexrays.cot_cast:
        return _to_expr(node.x)

    elif op == ida_hexrays.cot_add:
        return _Add(_to_expr(node.x), _to_expr(node.y))

    elif op == ida_hexrays.cot_sub:
        return _Sub(_to_expr(node.x), _to_expr(node.y))

    else:
        return _Unknown()
