"""
Helpers to parse `ida_lines` format.
"""

import re
import typing as ty
from dataclasses import dataclass
from itertools import groupby, repeat

import ida_hexrays
import ida_lines
import ida_name
import typing_extensions as tye
from idaapi import BADADDR
from more_itertools import before_and_after, nth, peekable

from decompai_client import AddressDetail, LVarDetail, Range, RangeDetail
from decompai_ida import api

_CFunc: tye.TypeAlias = ty.Union[ida_hexrays.cfunc_t, ida_hexrays.cfuncptr_t]


def get_ranges_sync(func: _CFunc) -> ty.Iterator[Range]:
    current_line_index = 0

    func_lines = _FuncLines.from_func(func)  # type: ignore
    arg_names: set[str] = {lvar.name for lvar in func.lvars if lvar.is_arg_var}  # type: ignore

    for line in func_lines.comment:
        current_line_index += len(_strip_codes(line)) + 1

    for line in func_lines.signature:
        for range in _arg_lvar_ranges(line, arg_names):
            yield _offset_range(range, current_line_index)
        current_line_index += len(_strip_codes(line)) + 1

    for line in func_lines.body:
        for range in _parse_ranges(func, line):
            for narrowed_range in _narrow_range(line, range):
                yield _offset_range(narrowed_range, current_line_index)
        current_line_index += len(_strip_codes(line)) + 1


def _offset_range(range: Range, offset: int) -> Range:
    return Range(
        start=range.start + offset,
        length=range.length,
        detail=range.detail,
    )


def _parse_ranges(func: _CFunc, line: str) -> ty.Iterator[Range]:
    ctree_item = ida_hexrays.ctree_item_t()

    def pos_and_tags():
        pos = 0
        for _, tag_text in _tags(line):
            yield pos, tag_text
            pos += len(tag_text)

    def detail_at(i: int) -> ty.Optional[RangeDetail]:
        func.get_line_item(
            line,
            i,
            True,
            None,  # type: ignore
            ctree_item,
            None,  # type: ignore
        )
        return _detail_from_ctree_item(ctree_item)

    tags_and_details = (
        (pos, tag, detail_at(pos)) for pos, tag in pos_and_tags()
    )
    tag_runs = groupby(tags_and_details, lambda pair: pair[2])

    for detail, tags_and_details in tag_runs:
        if detail is not None:
            tags_and_details = peekable(tags_and_details)
            start, _, _ = tags_and_details.peek()
            length = sum(len(tag) for _, tag, _ in tags_and_details)
            yield Range(start=start, length=length, detail=detail)


def _strip_codes(text: str) -> str:
    return "".join(tag_text for _, tag_text in _tags(text))


def _tags(text: str) -> ty.Iterable[tuple[str, str]]:
    i = 0
    while i < len(text):
        tag_length = ida_lines.tag_advance(text[i:], 1)
        codes_length = ida_lines.tag_skipcodes(text[i:])
        tag_codes = text[i : i + codes_length]
        tag_text = text[i + codes_length : i + tag_length]
        yield tag_codes, tag_text
        i += tag_length


def _detail_from_ctree_item(
    ctree_item: ida_hexrays.ctree_item_t,
) -> ty.Optional[RangeDetail]:
    address = ctree_item.get_ea()
    if address != BADADDR:
        return RangeDetail(AddressDetail(address=api.format_address(address)))

    lvar = ctree_item.get_lvar()
    if lvar is not None:
        return RangeDetail(
            LVarDetail(name=lvar.name, is_arg=lvar.is_arg_var)  # type: ignore
        )


_NAME_PATTERN = re.compile(r"\b[a-z_]\w*", re.IGNORECASE)


def _narrow_range(line: str, range: Range) -> ty.Iterator[Range]:
    if range.detail is None:
        yield range
        return

    detail = range.detail.actual_instance
    assert detail is not None

    if isinstance(detail, AddressDetail):
        address_name = ida_name.get_short_name(
            api.parse_address(detail.address)
        )
        yield from _narrow_when_name_is(line, range, address_name)
    elif isinstance(detail, LVarDetail):
        lvar_name = detail.name
        yield from _narrow_when_name_is(line, range, lvar_name)
    else:
        _: tye.Never = detail


def _narrow_when_name_is(
    line: str, range: Range, name: ty.Optional[str] = None
) -> ty.Iterator[Range]:
    range_text = _strip_codes(line)[range.start : range.start + range.length]
    for name_match in _NAME_PATTERN.finditer(range_text):
        if name is None or name_match.group(0) == name:
            yield Range(
                start=range.start + name_match.start(),
                length=len(name_match.group(0)),
                detail=range.detail,
            )


def _arg_lvar_ranges(
    line: str, arg_names: ty.Collection[str]
) -> ty.Iterator[Range]:
    for name_match in _NAME_PATTERN.finditer(_strip_codes(line)):
        name = name_match.group(0)
        if name in arg_names:
            yield Range(
                start=name_match.start(),
                length=len(name),
                detail=RangeDetail(LVarDetail(name=name, is_arg=True)),
            )


_ADDRESS_CODE = chr(ida_lines.COLOR_ADDR)


@dataclass
class _FuncLines:
    comment: tuple[str, ...]
    signature: tuple[str, ...]
    body: tuple[str, ...]

    @staticmethod
    def from_func(func: _CFunc) -> "_FuncLines":
        def no_address(line: str) -> bool:
            return not any(
                _ADDRESS_CODE in tag_codes for tag_codes, _ in _tags(line)
            )

        def is_comment(line: str) -> bool:
            return _strip_codes(line).startswith("//")

        lines: ty.Iterator[str] = (
            pseudocode_line.line for pseudocode_line in func.get_pseudocode()
        )

        preamble_lines, body_lines = before_and_after(no_address, lines)
        comment_lines, signature_lines = before_and_after(
            is_comment, preamble_lines
        )
        return _FuncLines(
            comment=tuple(comment_lines),
            signature=tuple(signature_lines),
            body=tuple(body_lines),
        )


def get_line_ids(
    cfunc: ida_hexrays.cfunc_t,
) -> ty.Iterator[str]:
    """
    Yield stable IDs
    """
    item = ida_hexrays.ctree_item_t()
    sv_lines = list(cfunc.get_pseudocode())

    yield from repeat("header", cfunc.hdrlines)
    pending = 0
    for sv_line in sv_lines[cfunc.hdrlines :]:
        cfunc.get_line_item(
            sv_line.line,
            0,
            True,
            None,  # type: ignore
            None,  # type: ignore
            item,
        )
        if item.citype == ida_hexrays.VDI_TAIL and (
            item.loc.itp > ida_hexrays.ITP_INNER_LAST  # type: ignore
        ):
            loc = item.loc  # type: ignore
            yield from repeat(
                f"{loc.ea:x}-{loc.itp:x}",
                pending + 1,
            )
            pending = 0
        else:
            pending += 1
    yield from repeat("tail", pending)


def line_id_to_index(
    cfunc: ida_hexrays.cfunc_t, stable_id: str
) -> ty.Optional[int]:
    """
    Given a stable ID, return the first current (0-based) line number, or None.
    """
    for i, line_id in enumerate(get_line_ids(cfunc)):
        if line_id == stable_id:
            return i
    return None


def line_index_to_id(
    cfunc: ida_hexrays.cfunc_t, index: int
) -> ty.Optional[str]:
    """
    Given a current (0-based) line number, return its stable ID, or None.
    """
    return nth(get_line_ids(cfunc), index)


def get_line_addresses(
    cfunc: ida_hexrays.cfunc_t,
) -> ty.Iterator[int]:
    """
    Yield address per pseudocode line
    """
    item = ida_hexrays.ctree_item_t()
    sv_lines = list(cfunc.get_pseudocode())

    yield from repeat(cfunc.entry_ea, cfunc.hdrlines)
    for sv_line in sv_lines[cfunc.hdrlines :]:
        cfunc.get_line_item(
            sv_line.line,
            0,
            True,
            None,  # type: ignore
            None,  # type: ignore
            item,
        )
        yield item.loc.ea  # type: ignore
