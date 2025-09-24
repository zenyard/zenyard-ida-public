from collections import defaultdict
from dataclasses import dataclass
import hashlib
from itertools import groupby
import json
import re
import typing as ty

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_name
import ida_search
import ida_segment
import idautils
from idaapi import BADADDR
from more_itertools import ilen, pairwise, take

from decompai_client import AddressDetail, LineRange, RangeDetail
from decompai_client.models import (
    Function,
    Thunk,
    GlobalVariable,
    DecompilerNote,
)
from decompai_ida import api, inferences, lines, logger
from decompai_ida.model import Model, Object
from decompai_ida.transform_code import transform_code

_IGNORED_SEGMENTS = {
    "extern",
    ".plt",
    ".plt.got",
    ".plt.sec",
    ".got",
    "__stubs",
    "__objc_stubs",
    # TODO: PE, Mach-O segments?
}


_MAX_INSTRUCTIONS_TO_DECOMPILE_WITHOUT_WAITBOX = 0x2000
_MAX_INSTRUCTIONS_TO_DECOMPILE = 0x20000
"""
Skip decompiling functions larger than this. These may cause decompiler to hang for a
long time, and will probably be too large for model.
"""

_MANGLED_NAME_CLEANUP_REGEX = re.compile(r"^(?:j_)+|(?:_\d+)+$")


def _clean_mangled_name(name: str) -> str:
    r"""
    Clean IDA-generated mangled name by removing common prefixes and suffixes.

    Removes:
    - j_ prefixes (can occur multiple times)
    - _\d+ suffixes (can occur multiple times)
    """
    return _MANGLED_NAME_CLEANUP_REGEX.sub("", name)


@dataclass(frozen=True)
class Symbol:
    address: int
    type: ty.Literal["function", "global_variable"]


def _is_padding_function_sync(address: int) -> bool:
    func = ida_funcs.get_func(address)
    if func is None or func.start_ea != address:
        return False

    if _count_instructions(address) != 1:
        return False

    if any(True for _ in idautils.XrefsTo(address)):
        return False

    return True


def _is_nullsub_sync(address: int) -> bool:
    name = ida_name.get_name(address)
    return name.startswith("nullsub_")


def all_object_symbols_sync() -> ty.Iterator[Symbol]:
    for segment_base in idautils.Segments():
        segment = ida_segment.getseg(segment_base)

        if not _is_object_segment(segment):
            continue

        segment_end = segment_base + segment.size()  # type: ignore
        yield from (
            Symbol(ea, "function")
            for ea in idautils.Functions(segment_base, segment_end)
            if not _is_padding_function_sync(ea) and not _is_nullsub_sync(ea)
        )

    # Get all global variables with references from code
    current_address = 0
    while (
        current_address := (
            ida_search.find_data(current_address, ida_search.SEARCH_DOWN)
        )
    ) != BADADDR:
        name = ida_name.get_name(current_address)
        # TODO: Currently after first inference, a global variable is no longer uploaded
        if not ida_name.is_uname(name) and any(
            ida_funcs.get_func(xref.frm) is not None  # type: ignore
            for xref in idautils.XrefsTo(current_address)
        ):
            yield Symbol(current_address, "global_variable")


# Note - decompiling a function actually requires writing to the DB, probably to
# cache results. Using `read` here results in failed decompilations.
def read_object_sync(
    address: int,
    *,
    model: Model,
    use_decompilation_cache: bool = False,
    show_wait_box: bool = False,
) -> Object:
    """
    Read object at address.

    If `func_graph` is available, it will be used to avoid traversing the
    function for calls.
    """
    address_flags = ida_bytes.get_full_flags(address)
    name = ida_name.get_short_name(address)
    if ida_bytes.is_data(address_flags) or ida_bytes.is_unknown(address_flags):
        inference_seq_number = _get_inference_seq_number(model=model)
        has_known_name = inferences.has_user_defined_name_sync(
            address, model=model
        )
        result = GlobalVariable(
            address=api.format_address(address),
            name=name,
            has_known_name=has_known_name,
            inference_seq_number=inference_seq_number,
            uses=_get_accesses(address),
        )
    else:
        func = ida_funcs.get_func(address)
        assert func is not None
        assert func.start_ea == address

        is_thunk = bool(func.flags & ida_funcs.FUNC_THUNK)

        inference_seq_number = _get_inference_seq_number(model=model)

        if is_thunk:
            target, _ = ida_funcs.calc_thunk_func_target(func)
            if target == BADADDR:
                raise Exception("Can't find thunk target")

            # Try decompiling to make HexRays improve typing on this thunk, and to
            # avoid detecting type change if user decompiles this later.
            try:
                _decompile(
                    func,
                    use_decompilation_cache=use_decompilation_cache,
                    show_wait_box=show_wait_box,
                )
            except Exception as ex:
                logger.get().warning(
                    "Error while decompiling thunk",
                    address=address,
                    exc_info=ex,
                )

            result = Thunk(
                address=api.format_address(address),
                name=name,
                target=api.format_address(target),
                inference_seq_number=inference_seq_number,
            )

        else:
            decompiled = _decompile(
                func,
                use_decompilation_cache=use_decompilation_cache,
                show_wait_box=show_wait_box,
            )

            has_known_name = inferences.has_user_defined_name_sync(
                address, model=model
            )

            mangled_name = (
                _clean_mangled_name(ida_name.get_name(address))
                if has_known_name
                else None
            )
            result = Function(
                address=api.format_address(address),
                name=name,
                code=str(decompiled),
                calls=_get_calls(address),
                has_known_name=has_known_name,
                ranges=list(lines.get_ranges_sync(decompiled)),
                inference_seq_number=inference_seq_number,
                line_ranges=list(_get_line_ranges_for_func(decompiled)),
                mangled_name=mangled_name,
                decompiler_notes=list(_get_decompiler_notes(decompiled)),
            )

    validate_object(result)
    return result


def _decompile(
    func: ida_funcs.func_t,
    *,
    use_decompilation_cache: bool,
    show_wait_box: bool,
) -> ida_hexrays.cfunc_t:
    instructions = _count_instructions(func.start_ea)
    if instructions >= _MAX_INSTRUCTIONS_TO_DECOMPILE:
        raise Exception("Not decompiling, too big")

    flags = 0
    if not use_decompilation_cache:
        flags |= ida_hexrays.DECOMP_NO_CACHE
    if (
        instructions < _MAX_INSTRUCTIONS_TO_DECOMPILE_WITHOUT_WAITBOX
        or not show_wait_box
    ):
        flags |= ida_hexrays.DECOMP_NO_WAIT

    failure = ida_hexrays.hexrays_failure_t()
    decompiled = ida_hexrays.decompile_func(func, failure, flags)

    if decompiled is None:
        raise Exception(f"Can't decompile: {failure.desc()}")
    return ty.cast(ida_hexrays.cfunc_t, decompiled)


def hash_object(obj: Object) -> bytes:
    if isinstance(obj, Function):
        obj = _reduct_object_references_from_code(obj)

    obj = _reduct_inference_seq_number(obj)

    data = json.dumps(
        obj.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    return hashlib.blake2b(data, digest_size=8).digest()


def is_in_ignored_segment_sync(address: int) -> bool:
    segment = ida_segment.getseg(address)
    return ida_segment.get_segm_name(segment) in _IGNORED_SEGMENTS


def _is_object_segment(segment: ida_segment.segment_t) -> bool:
    # Currently all objects are in code segments.
    if ida_segment.get_segm_class(segment) != "CODE":
        return False

    if ida_segment.get_segm_name(segment) in _IGNORED_SEGMENTS:
        return False

    return True


def _get_inference_seq_number(model: Model) -> ty.Optional[int]:
    # Inference sequence number is cursor minus one.
    revision_cursor = model.inference_cursor.get_sync()
    return revision_cursor - 1 if revision_cursor is not None else None


def _get_calls(address: int) -> list[str]:
    results = set[int]()
    for item in idautils.FuncItems(address):
        for code_ref in idautils.CodeRefsFrom(item, flow=False):
            func = ida_funcs.get_func(code_ref)
            if func is None or func.start_ea == address:
                continue
            results.add(func.start_ea)
    return [api.format_address(result) for result in results]


def _get_accesses(address: int) -> list[str]:
    return list(
        {
            api.format_address(accessing_function.start_ea)
            for xref in idautils.XrefsTo(address)
            if (accessing_function := ida_funcs.get_func(xref.frm)) is not None  # type: ignore
        }
    )


def _count_instructions(address: int) -> int:
    return ilen(
        take(_MAX_INSTRUCTIONS_TO_DECOMPILE, idautils.FuncItems(address))
    )


def _reduct_object_references_from_code(func: Function) -> Function:
    """
    Gets code but replaces all references to other objects with `[obj]`.

    This is useful for hashing, so that changing other objects doesn't change
    change of this object.
    """

    def reduct_object_reference(original: str, detail: RangeDetail):
        if (
            isinstance(detail.actual_instance, AddressDetail)
            and (detail.actual_instance.address != func.address)
            and _is_object_address(
                api.parse_address(detail.actual_instance.address)
            )
        ):
            return "[obj]"
        else:
            return original

    return transform_code(func, reduct_object_reference)


def _reduct_inference_seq_number(obj: Object) -> Object:
    return obj.model_copy(update={"inference_seq_number": 0})


def _is_object_address(address: int) -> bool:
    func = ida_funcs.get_func(address)

    if func is None or address != func.start_ea:
        return False

    if is_in_ignored_segment_sync(address):
        return False

    return True


def _get_line_ranges_for_func(
    cfunc: ida_hexrays.cfunc_t,
) -> ty.Iterator[LineRange]:
    for key, group in groupby(lines.get_line_ids(cfunc)):
        yield LineRange(id=key, line_count=ilen(group))


_WARNINGS_TO_UPLOAD = {
    ida_hexrays.WARN_UNDEF_LVAR,
}


def _get_decompiler_notes(
    cfunc: ida_hexrays.cfunc_t,
) -> ty.Iterator[DecompilerNote]:
    warnings_per_address = defaultdict[int, list[str]](list)

    for warning in cfunc.get_warnings():
        if warning.id in _WARNINGS_TO_UPLOAD:
            warnings_per_address[warning.ea].append(warning.text)

    for line_number, line_address in enumerate(
        lines.get_line_addresses(cfunc), start=1
    ):
        for warning in warnings_per_address.pop(line_address, ()):
            yield DecompilerNote(line_number=line_number, text=warning)


def validate_object(obj: Object):
    """
    Throws `ValueError` if object is not valid.
    """
    if isinstance(obj, Function):
        _validate_function(obj)


def _validate_function(func: Function):
    ranges = func.ranges or ()
    # Validate ranges are within code bounds
    if any(r.start < 0 or r.start + r.length > len(func.code) for r in ranges):
        raise ValueError("Range out of code bounds")

    # Validate ranges do not overlap
    sorted_ranges = sorted(ranges, key=lambda r: r.start)
    if any(
        range2.start < range1.start + range1.length
        for range1, range2 in pairwise(sorted_ranges)
    ):
        raise ValueError("Overlapping ranges")

    # If present, line ranges must cover the entire function.
    if func.line_ranges is not None:
        covered_lines = sum(range.line_count for range in func.line_ranges)
        code_lines = func.code.rstrip("\n").count("\n") + 1
        if covered_lines != code_lines:
            raise ValueError(
                f"Code has {code_lines} lines but ranges cover {covered_lines} lines"
            )
