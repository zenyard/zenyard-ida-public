from dataclasses import dataclass
from itertools import dropwhile, islice
import re
import typing as ty

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_name
import ida_nalt
import ida_segment
import ida_typeinf
import idaapi
import idautils

from pydantic import BaseModel, Field
from decompai_ida import ida_tasks, logger
from decompai_ida.model import Model
from decompai_ida.swift_utils import (
    find_latest_swift_function_inference_sync,
    is_swift_binary_sync,
)
from langchain.tools import tool

Address = ty.Annotated[str, "The address in hex string"]

_SymbolName: ty.TypeAlias = ty.Annotated[
    str,
    "Symbol name to resolve to an address. Can be a function name or a global variable name.",
]


@dataclass(frozen=True)
class CopilotTools:
    common: list[ty.Any]
    exploration: list[ty.Any]
    modification: list[ty.Any]

    def all_tools(self) -> list[ty.Any]:
        return [*self.common, *self.exploration, *self.modification]


@dataclass(frozen=True)
class Function:
    name: str
    address: Address
    swift_source_available: bool

    @staticmethod
    def from_ea(model: Model, ea: int) -> "Function":
        if not is_swift_binary_sync():
            swift_source_available = False
        else:
            swift_function = find_latest_swift_function_inference_sync(
                model, ea
            )
            swift_source_available = swift_function is not None

        return Function(
            ida_name.get_name(ea),
            format_address(ea),
            swift_source_available=swift_source_available,
        )


@dataclass(frozen=True)
class LocalType:
    name: str
    definition: str


@dataclass(frozen=True)
class Xref:
    from_address: Address
    to_address: Address
    kind: str
    xref_type_name: str
    function_address: ty.Optional[Address]
    function_name: ty.Optional[str]


@dataclass(frozen=True)
class StringItem:
    address: Address
    length: int
    type: str
    value: str


@dataclass(frozen=True)
class Segment:
    name: str
    start_address: Address
    end_address: Address
    size: int


@dataclass(frozen=True)
class ImportedSymbol:
    module: str
    name: str
    address: ty.Optional[Address]


@dataclass(frozen=True)
class ExportedSymbol:
    ordinal: int
    name: str
    address: Address


@dataclass(frozen=True)
class AddressDetails:
    address: Address
    name: ty.Optional[str]
    segment: ty.Optional[str]
    function_address: ty.Optional[Address]
    function_name: ty.Optional[str]
    is_code: bool
    is_data: bool
    comment: ty.Optional[str]
    bytes_preview: str


class BatchResult(BaseModel, frozen=True):
    """Result of a batch operation"""

    success_count: int
    failure_count: int
    errors: list[str]  # Human-readable error messages


T = ty.TypeVar("T")
T2 = ty.TypeVar("T2")


@dataclass(frozen=True)
class PagedResults(ty.Generic[T]):
    results: list[T]
    next_cursor: ty.Optional[str]

    def map(self, func: ty.Callable[[T], T2]) -> "PagedResults[T2]":
        return PagedResults(
            results=[func(result) for result in self.results],
            next_cursor=self.next_cursor,
        )


def get_function(address: str) -> ida_funcs.func_t:
    func = ida_funcs.get_func(int(address, 16))
    if func is None:
        raise Exception(f"Failed to retrieve function from address: {address}")
    return func


def _perform_batch_operations(
    *,
    items: ty.Iterable[T],
    operation: ty.Callable[[T], None],
    operation_name: str,
) -> str:
    success_count = 0
    failure_count = 0
    errors = list[str]()

    for item in items:
        try:
            operation(item)
            success_count += 1
        except Exception as ex:
            failure_count += 1
            errors.append(str(ex))
            logger.warning(
                f"Error in batch {operation_name} with item {item}", exc_info=ex
            )

    _update_pseudocode_viewer()
    result = BatchResult(
        success_count=success_count, failure_count=failure_count, errors=errors
    )
    return result.model_dump_json()


def decompile_function_sync(address: str) -> str:
    func = get_function(address)
    failure = ida_hexrays.hexrays_failure_t()
    decompiled = ida_hexrays.decompile_func(
        func, failure, ida_hexrays.DECOMP_NO_WAIT
    )
    if not decompiled:
        raise Exception(f"Can't decompile: {failure.desc()}")
    return str(decompiled)


def get_swift_source_sync(model: Model, address: str) -> str:
    func = get_function(address)
    swift_function = find_latest_swift_function_inference_sync(
        model, func.start_ea
    )
    if swift_function is None:
        raise Exception(
            f"No Swift source code available for function at {address}"
        )
    return swift_function.source


def get_symbol_address_by_name_sync(symbol_name: str) -> Address:
    name_ea = ida_name.get_name_ea(0, symbol_name)
    if name_ea != idaapi.BADADDR:
        return format_address(name_ea)
    else:
        # TODO: Handle mangled names
        raise Exception("Failed to resolve symbol to address")


def get_current_function_sync(model: Model) -> ty.Optional[Function]:
    current_address = idaapi.get_screen_ea()
    func = ida_funcs.get_func(current_address)
    if func is None:
        raise Exception(
            f"There's no function in address: {format_address(current_address)}"
        )
    return Function.from_ea(model, func.start_ea)


def rename_function_local_variables_sync(
    address: str,
    variable_renames: dict[str, str],
) -> str:
    func = get_function(address)

    def rename_one_variable(item: tuple[str, str]):
        from_name, to_name = item
        success = ida_hexrays.rename_lvar(func.start_ea, from_name, to_name)
        if not success:
            raise Exception(f"Failed renaming '{from_name}' to '{to_name}'")

    return _perform_batch_operations(
        items=variable_renames.items(),
        operation=rename_one_variable,
        operation_name="rename variable",
    )


def rename_symbols_sync(
    symbol_renames: dict[str, str],
) -> str:
    def rename_one_symbol(item: tuple[str, str]):
        address, new_name = item
        if not ida_name.set_name(int(address, 16), new_name):
            raise Exception(f"Failed to rename {address} to {new_name}")

    return _perform_batch_operations(
        items=symbol_renames.items(),
        operation=rename_one_symbol,
        operation_name="rename symbol",
    )


def list_calling_functions_sync(
    model: Model,
    address: str,
    cursor: ty.Optional[str] = None,
    page_size: int = 200,
) -> PagedResults[Function]:
    func = get_function(address)
    return _paginate_results(
        sorted(
            func.start_ea
            for ref_ea in idautils.CodeRefsTo(func.start_ea, False)
            if (func := ida_funcs.get_func(ref_ea)) is not None
        ),
        by=format_address,
        cursor=cursor,
        page_size=page_size,
    ).map(lambda ea: Function.from_ea(model, ea))


def get_function_comment_sync(address: str) -> ty.Optional[str]:
    func = get_function(address)
    return ida_funcs.get_func_cmt(func, False)


def set_function_comments_sync(
    comment_updates: dict[str, ty.Optional[str]],
) -> str:
    def set_one_comment(item: tuple[str, ty.Optional[str]]):
        address, comment = item
        func = get_function(address)
        ida_funcs.set_func_cmt(func, comment or "", False)

    return _perform_batch_operations(
        items=comment_updates.items(),
        operation=set_one_comment,
        operation_name="set comment",
    )


def set_function_prototypes_sync(
    prototype_updates: dict[str, str],
) -> str:
    def set_one_prototype(item: tuple[str, str]):
        address, new_prototype = item
        if not new_prototype.endswith(";"):
            new_prototype += ";"
        func = get_function(address)
        new_tinfo = ida_typeinf.tinfo_t()
        if (
            ida_typeinf.parse_decl(
                new_tinfo,
                None,  # type: ignore
                new_prototype,
                ida_typeinf.PT_SIL,
            )
            is None
        ):  # type: ignore
            raise Exception(f"Failed to parse c declaration: {new_prototype}")
        # TODO: Could not use ida_typeinf.ida_typeinf.TINFO_GUESSED, not sure why
        if not ida_typeinf.apply_tinfo(
            func.start_ea, new_tinfo, ida_typeinf.TINFO_DEFINITE
        ):
            raise Exception(
                f"Failed to apply tinfo_t to function prototype: {new_tinfo}"
            )

    return _perform_batch_operations(
        items=prototype_updates.items(),
        operation=set_one_prototype,
        operation_name="set prototype",
    )


def get_local_types_sync(
    cursor: ty.Optional[str] = None, page_size: int = 200
) -> PagedResults[LocalType]:
    idati = ida_typeinf.get_idati()
    tinfo = ida_typeinf.tinfo_t()

    def create_local_type(type_name: str) -> LocalType:
        definition = tinfo._print(  # type: ignore
            name=type_name,
            prtype_flags=(
                ida_typeinf.PRTYPE_TYPE
                | ida_typeinf.PRTYPE_SEMI
                | ida_typeinf.PRTYPE_MULTI
                | ida_typeinf.PRTYPE_DEF  # type: ignore
            ),
        )
        return LocalType(name=type_name, definition=definition)

    # Create all valid local types sorted alphabetically
    local_types = [
        create_local_type(type_name)
        for type_name in sorted(idati.type_names)  # type: ignore
        if tinfo.get_named_type(idati, type_name)
    ]

    return _paginate_results(
        local_types,
        by=lambda local_type: local_type.name,  # Use type name as cursor
        cursor=cursor,
        page_size=page_size,
    )


def _paginate_functions(
    model: Model,
    cursor: ty.Optional[str],
    page_size: int,
    filter_predicate: ty.Callable[[int], bool],
) -> PagedResults[Function]:
    """
    Generic pagination helper for IDA functions.

    Args:
        model: Model instance for Swift source availability checking
        cursor: Optional cursor for pagination (hex address string)
        page_size: Number of functions to return per page
        filter_predicate: Function that takes func_ea and returns True if function should be included

    Returns:
        PagedResults containing functions and optional next cursor
    """

    start_ea = int(cursor, 16) + 1 if cursor else 0
    return _paginate_results(
        (
            func_ea
            for func_ea in idautils.Functions(start_ea)
            if filter_predicate(func_ea)
        ),
        by=format_address,
        cursor=cursor,
        page_size=page_size,
    ).map(lambda ea: Function.from_ea(model, ea))


def search_function_comments_sync(
    model: Model,
    regex_pattern: str,
    cursor: ty.Optional[str] = None,
    page_size: int = 200,
) -> PagedResults[Function]:
    def comment_matches(func_ea: int) -> bool:
        func = ida_funcs.get_func(func_ea)
        if not func:
            return False
        comment = ida_funcs.get_func_cmt(func, False)
        if comment is None:
            return False
        return re.search(regex_pattern, comment) is not None

    return _paginate_functions(model, cursor, page_size, comment_matches)


def search_swift_functions_sync(
    model: Model,
    regex_pattern: str,
    cursor: ty.Optional[str] = None,
    page_size: int = 200,
) -> PagedResults[Function]:
    def swift_source_matches(func_ea: int) -> bool:
        swift_function = find_latest_swift_function_inference_sync(
            model, func_ea
        )
        if swift_function is None:
            return False
        return re.search(regex_pattern, swift_function.source) is not None

    return _paginate_functions(model, cursor, page_size, swift_source_matches)


def list_functions_sync(
    model: Model,
    filter: ty.Optional[str],
    cursor: ty.Optional[str] = None,
    page_size: int = 200,
) -> PagedResults[Function]:
    def name_matches(func_ea: int) -> bool:
        if filter is None:
            return True
        func_name = ida_name.get_name(func_ea)
        if func_name is None:
            return False
        return re.search(filter, func_name) is not None

    return _paginate_functions(model, cursor, page_size, name_matches)


def list_called_functions_sync(
    model: Model,
    address: str,
    cursor: ty.Optional[str] = None,
    page_size: int = 200,
) -> PagedResults[Function]:
    func = get_function(address)
    called_functions = sorted(
        {
            called_func.start_ea
            for item_ea in idautils.FuncItems(func.start_ea)
            for ref_ea in idautils.CodeRefsFrom(item_ea, False)
            if (called_func := ida_funcs.get_func(ref_ea)) is not None
        }
    )
    return _paginate_results(
        called_functions,
        by=format_address,
        cursor=cursor,
        page_size=page_size,
    ).map(lambda ea: Function.from_ea(model, ea))


def get_xrefs_to_sync(
    address: str,
    cursor: ty.Optional[str] = None,
    page_size: int = 200,
) -> PagedResults[Xref]:
    target_ea = int(address, 16)
    xrefs = sorted(
        (_xref_from_ida(xref) for xref in idautils.XrefsTo(target_ea, 0)),
        key=_xref_cursor_to,
    )
    return _paginate_results(
        xrefs,
        by=_xref_cursor_to,
        cursor=cursor,
        page_size=page_size,
    )


def get_xrefs_from_sync(
    address: str,
    cursor: ty.Optional[str] = None,
    page_size: int = 200,
) -> PagedResults[Xref]:
    ea = int(address, 16)
    func = ida_funcs.get_func(ea)
    merged: list[Xref] = []
    if func is not None and func.start_ea == ea:
        for item_ea in idautils.FuncItems(func.start_ea):
            merged.extend(
                _xref_from_ida(xref) for xref in idautils.XrefsFrom(item_ea, 0)
            )
    else:
        merged.extend(
            _xref_from_ida(xref) for xref in idautils.XrefsFrom(ea, 0)
        )
    deduped = {_xref_cursor_from(x): x for x in merged}
    xrefs = sorted(deduped.values(), key=_xref_cursor_from)
    return _paginate_results(
        xrefs,
        by=_xref_cursor_from,
        cursor=cursor,
        page_size=page_size,
    )


def list_strings_sync(
    filter: ty.Optional[str],
    cursor: ty.Optional[str] = None,
    page_size: int = 200,
) -> PagedResults[StringItem]:
    strings = idautils.Strings(default_setup=True)
    pattern = re.compile(filter) if filter is not None else None
    results = sorted(
        (
            StringItem(
                address=format_address(string.ea),
                length=int(string.length),
                type=_string_type_label(int(string.strtype)),
                value=str(string),
            )
            for string in strings
            if pattern is None or pattern.search(str(string)) is not None
        ),
        key=lambda string: string.address,
    )
    return _paginate_results(
        results,
        by=lambda string: string.address,
        cursor=cursor,
        page_size=page_size,
    )


def list_segments_sync(
    cursor: ty.Optional[str] = None,
    page_size: int = 200,
) -> PagedResults[Segment]:
    segments = sorted(
        (
            Segment(
                name=segment.name,
                start_address=format_address(segment.start_ea),
                end_address=format_address(segment.end_ea),
                size=int(segment.end_ea - segment.start_ea),
            )
            for i in range(ida_segment.get_segm_qty())
            if (segment := ida_segment.getnseg(i)) is not None
        ),
        key=lambda segment: segment.start_address,
    )
    return _paginate_results(
        segments,
        by=lambda segment: segment.start_address,
        cursor=cursor,
        page_size=page_size,
    )


def list_imports_sync(
    cursor: ty.Optional[str] = None,
    page_size: int = 200,
) -> PagedResults[ImportedSymbol]:
    imported_symbols = list[ImportedSymbol]()
    module_count = ida_nalt.get_import_module_qty()
    for module_index in range(module_count):
        module_name = ida_nalt.get_import_module_name(module_index)
        normalized_module_name = module_name or f"module_{module_index}"

        def _collect_import(
            ea: int, name: ty.Optional[str], ordinal: int
        ) -> bool:
            symbol_name = name or f"ordinal_{ordinal}"
            imported_symbols.append(
                ImportedSymbol(
                    module=normalized_module_name,
                    name=symbol_name,
                    address=(
                        format_address(ea) if ea != idaapi.BADADDR else None
                    ),
                )
            )
            return True

        ida_nalt.enum_import_names(module_index, _collect_import)

    imported_symbols.sort(key=lambda symbol: (symbol.module, symbol.name))
    return _paginate_results(
        imported_symbols,
        by=_import_symbol_cursor,
        cursor=cursor,
        page_size=page_size,
    )


def list_exports_sync(
    cursor: ty.Optional[str] = None,
    page_size: int = 200,
) -> PagedResults[ExportedSymbol]:
    exports = sorted(
        (
            ExportedSymbol(
                ordinal=int(ordinal),
                name=str(name) if name else "",
                address=format_address(int(ea)),
            )
            for _index, ordinal, ea, name in idautils.Entries()
        ),
        key=lambda item: item.address,
    )
    return _paginate_results(
        exports,
        by=lambda item: item.address,
        cursor=cursor,
        page_size=page_size,
    )


def read_data_at_address_sync(address: str, size: int = 64) -> str:
    data = ida_bytes.get_bytes(int(address, 16), size)
    if data is None:
        raise Exception(f"Failed to read bytes at {address}")
    hex_bytes = data.hex(" ")
    utf8_preview = "".join(
        c if (c.isprintable() or c in " \t\n\r") else "."
        for c in data.decode("utf-8", errors="surrogateescape")
    )
    return (
        f"Address: {address}\n"
        f"Size: {len(data)}\n"
        f"Hex: {hex_bytes}\n"
        f"UTF-8 preview (dots = non-printable or decoding issues): {utf8_preview}"
    )


def get_bytes_sync(address: str, size: int) -> str:
    data = ida_bytes.get_bytes(int(address, 16), size)
    if data is None:
        raise Exception(f"Failed to read bytes at {address}")
    return data.hex(" ")


def disassemble_function_sync(address: str, *, max_lines: int = 400) -> str:
    func = get_function(address)
    lines = list[str]()
    for item_ea in idautils.FuncItems(func.start_ea):
        if len(lines) >= max_lines:
            lines.append(
                f"... (truncated after {max_lines} lines;  "
                "Increase the max_lines parameter to get more lines)"
            )
            break
        disasm = ida_lines.tag_remove(
            ida_lines.generate_disasm_line(item_ea, 0) or ""
        ).strip()
        lines.append(f"{format_address(item_ea)}: {disasm}")
    return "\n".join(lines)


def get_current_address_sync() -> Address:
    return format_address(idaapi.get_screen_ea())


def get_address_details_sync(address: str) -> AddressDetails:
    ea = int(address, 16)
    flags = ida_bytes.get_full_flags(ea)
    segment = ida_segment.getseg(ea)
    func = ida_funcs.get_func(ea)
    bytes_preview = ida_bytes.get_bytes(ea, 16) or b""
    return AddressDetails(
        address=format_address(ea),
        name=ida_name.get_name(ea) or None,
        segment=segment.name if segment is not None else None,
        function_address=(
            format_address(func.start_ea) if func is not None else None
        ),
        function_name=ida_name.get_name(func.start_ea)
        if func is not None
        else None,
        is_code=ida_bytes.is_code(flags),
        is_data=ida_bytes.is_data(flags),
        comment=idaapi.get_cmt(ea, False),
        bytes_preview=bytes_preview.hex(" "),
    )


_IMPORT_CURSOR_SEP = "\x1f"


def _import_symbol_cursor(symbol: ImportedSymbol) -> str:
    return f"{symbol.module}{_IMPORT_CURSOR_SEP}{symbol.name}"


def _string_type_label(strtype: int) -> str:
    try:
        label = ida_nalt.encoding_from_strtype(strtype)
    except Exception:
        return str(strtype)
    return label if label else str(strtype)


def _describe_xref(xref: ty.Any) -> tuple[str, str]:
    xref_type = int(getattr(xref, "type"))
    is_code = bool(getattr(xref, "iscode", False))
    kind = "code" if is_code else "data"
    try:
        name = idautils.XrefTypeName(xref_type)
    except Exception:
        name = ""
    type_name = name.strip() if name else str(xref_type)
    return kind, type_name


def _xref_from_ida(xref: ty.Any) -> Xref:
    from_ea = int(getattr(xref, "frm"))
    to_ea = int(getattr(xref, "to"))
    kind, xref_type_name = _describe_xref(xref)
    func = ida_funcs.get_func(from_ea)
    return Xref(
        from_address=format_address(from_ea),
        to_address=format_address(to_ea),
        kind=kind,
        xref_type_name=xref_type_name,
        function_address=(
            format_address(func.start_ea) if func is not None else None
        ),
        function_name=ida_name.get_name(func.start_ea)
        if func is not None
        else None,
    )


def _xref_cursor_to(xref: Xref) -> str:
    return f"{xref.from_address}\x1f{xref.kind}\x1f{xref.xref_type_name}"


def _xref_cursor_from(xref: Xref) -> str:
    return f"{xref.to_address}\x1f{xref.kind}\x1f{xref.xref_type_name}"


def _update_pseudocode_viewer():
    current_vdui = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_viewer())

    if current_vdui is None:
        return

    if not current_vdui.visible():
        return

    current_vdui.refresh_view(True)


def format_address(addr: int) -> str:
    return f"0x{addr:016x}"


def _paginate_results(
    objects_iter: ty.Iterable[T],
    *,
    by: ty.Callable[[T], str],
    cursor: ty.Optional[str],
    page_size: int,
    max_pages: ty.Optional[int] = 20,
) -> PagedResults[T]:
    """
    Generic cursor-based pagination for any iterable of objects.

    Args:
        objects_iter: Iterable of objects to paginate
        by: Function that extracts a string cursor from an object
        cursor: Optional cursor string to continue pagination from
        page_size: Maximum number of objects to return per page
        max_pages: Optional limit on total pages available

    Returns:
        PagedResults containing results and optional next cursor
    """
    remaining_objects = list(
        dropwhile(
            lambda obj: (cursor is not None) and (by(obj) <= cursor),
            objects_iter,
        )
    )
    if max_pages is not None and len(remaining_objects) / page_size > max_pages:
        raise Exception(
            "Too many pages for the current operation. Try to narrow down your search."
        )
    results = list(
        islice(
            remaining_objects,
            page_size + 1,
        ),
    )
    if len(results) > page_size:
        results = results[:page_size]
        next_cursor = by(results[-1])
    else:
        next_cursor = None
    return PagedResults(results=results, next_cursor=next_cursor)


async def get_copilot_tools(model: Model):
    @tool()
    async def get_current_function() -> ty.Optional[Function]:
        """
        Returns the current function address and name, or None if not currently in a function.
        """
        return await ida_tasks.run(get_current_function_sync, model)

    @tool()
    async def get_symbol_address_by_name(symbol_name: _SymbolName) -> Address:
        """
        Get address of function or global variable given its name.
        """
        return await ida_tasks.run(get_symbol_address_by_name_sync, symbol_name)

    @tool()
    async def list_functions(
        filter: ty.Annotated[
            ty.Optional[str],
            "An optional regex to filter the list of functions",
        ],
        cursor: ty.Annotated[
            ty.Optional[str], "Optional hex address to start from"
        ] = None,
    ) -> PagedResults[Function]:
        "Returns a paginated list of functions (names and addresses) from ida"
        return await ida_tasks.run(list_functions_sync, model, filter, cursor)

    @tool()
    async def decompile_function(
        address: ty.Annotated[str, "Address of the function to decompile"],
    ) -> str:
        """Returns the decompiled code of the given function"""
        return await ida_tasks.run(decompile_function_sync, address)

    @tool()
    async def disassemble_function(
        address: ty.Annotated[str, "Address of the function to disassemble"],
        max_lines: ty.Annotated[
            int,
            "Maximum number of instruction lines to return (default 400)",
        ] = 400,
    ) -> str:
        """Returns the disassembly listing of the given function"""
        return await ida_tasks.run(
            disassemble_function_sync, address, max_lines=max_lines
        )

    @tool()
    async def rename_function_local_variables(
        address: ty.Annotated[str, "Address of the function"],
        variable_renames: ty.Annotated[
            dict[str, str],
            "Dict mapping old variable names to new names",
        ],
    ) -> str:
        """Rename multiple local variables in a single function"""
        return await ida_tasks.run(
            rename_function_local_variables_sync, address, variable_renames
        )

    @tool()
    async def rename_symbols(
        symbol_renames: ty.Annotated[
            dict[str, str],
            "Dict mapping addresses to new names",
        ],
    ) -> str:
        """Rename multiple symbols (functions or global variables) in a single batch"""
        return await ida_tasks.run(rename_symbols_sync, symbol_renames)

    @tool()
    async def list_calling_functions(
        address: ty.Annotated[str, "Address of the function being called"],
        cursor: ty.Annotated[ty.Optional[str], "Cursor for pagination"] = None,
    ) -> PagedResults[Function]:
        """
        Returns a list of functions that call the given function.
        If next_cursor is not empty that means there are more pages which can be fetched using the cursor parameter.
        """
        return await ida_tasks.run(
            list_calling_functions_sync, model, address, cursor
        )

    @tool()
    async def list_called_functions(
        address: ty.Annotated[str, "Address of the caller function"],
        cursor: ty.Annotated[ty.Optional[str], "Cursor for pagination"] = None,
    ) -> PagedResults[Function]:
        """Returns a list of functions called by the given function"""
        return await ida_tasks.run(
            list_called_functions_sync, model, address, cursor
        )

    @tool()
    async def get_xrefs_to(
        address: ty.Annotated[str, "Address being referenced"],
        cursor: ty.Annotated[ty.Optional[str], "Cursor for pagination"] = None,
    ) -> PagedResults[Xref]:
        """Returns cross references that point to the given address"""
        return await ida_tasks.run(get_xrefs_to_sync, address, cursor)

    @tool()
    async def get_xrefs_from(
        address: ty.Annotated[str, "Address emitting references"],
        cursor: ty.Annotated[ty.Optional[str], "Cursor for pagination"] = None,
    ) -> PagedResults[Xref]:
        """Returns cross references originating from the given address"""
        return await ida_tasks.run(get_xrefs_from_sync, address, cursor)

    @tool()
    async def get_function_comment(
        address: ty.Annotated[str, "Address of the function"],
    ) -> ty.Optional[str]:
        """Returns the function documentation for the given function"""
        return await ida_tasks.run(get_function_comment_sync, address)

    @tool()
    async def set_function_comments(
        comment_updates: ty.Annotated[
            dict[str, ty.Optional[str]],
            "Dict mapping addresses to comments (null to clear); Use 80 character lines and format this like a function documentation.",
        ],
    ) -> str:
        """Set comments on multiple functions in a single batch"""
        return await ida_tasks.run(set_function_comments_sync, comment_updates)

    @tool()
    async def set_function_prototypes(
        prototype_updates: ty.Annotated[
            dict[str, str],
            "Dict mapping addresses to C-style function prototypes",
        ],
    ) -> str:
        """Set prototypes on multiple functions in a single batch"""
        return await ida_tasks.run(
            set_function_prototypes_sync, prototype_updates
        )

    @tool()
    async def get_local_types(
        cursor: ty.Annotated[
            ty.Optional[str], "Optional cursor for pagination"
        ] = None,
    ) -> PagedResults[LocalType]:
        """Returns a paginated list of local types with their definitions"""
        return await ida_tasks.run(get_local_types_sync, cursor)

    @tool()
    async def search_function_comments(
        regex: ty.Annotated[
            str, "Regular expression pattern to search for in function comments"
        ],
        cursor: ty.Annotated[
            ty.Optional[str], "Optional hex address to start from"
        ] = None,
    ) -> PagedResults[Function]:
        """Returns a paginated list of functions with comments matching the given regex pattern"""
        return await ida_tasks.run(
            search_function_comments_sync, model, regex, cursor
        )

    @tool()
    async def list_strings(
        filter: ty.Annotated[
            ty.Optional[str],
            "Optional regex to filter string contents",
        ] = None,
        cursor: ty.Annotated[
            ty.Optional[str], "Optional address cursor to continue from"
        ] = None,
    ) -> PagedResults[StringItem]:
        """Returns a paginated list of strings from the current database"""
        return await ida_tasks.run(list_strings_sync, filter, cursor)

    @tool()
    async def list_segments(
        cursor: ty.Annotated[
            ty.Optional[str], "Optional segment start address cursor"
        ] = None,
    ) -> PagedResults[Segment]:
        """Returns a paginated list of memory segments"""
        return await ida_tasks.run(list_segments_sync, cursor)

    @tool()
    async def list_imports(
        cursor: ty.Annotated[ty.Optional[str], "Optional import cursor"] = None,
    ) -> PagedResults[ImportedSymbol]:
        """Returns a paginated list of imported symbols"""
        return await ida_tasks.run(list_imports_sync, cursor)

    @tool()
    async def list_exports(
        cursor: ty.Annotated[ty.Optional[str], "Optional export cursor"] = None,
    ) -> PagedResults[ExportedSymbol]:
        """Returns a paginated list of exported symbols"""
        return await ida_tasks.run(list_exports_sync, cursor)

    @tool()
    async def read_data_at_address(
        address: ty.Annotated[str, "Address to read bytes from"],
        size: ty.Annotated[
            int, "Maximum number of bytes to read (recommended: <= 64)"
        ] = 64,
    ) -> str:
        """Returns hex dump and UTF-8 preview of bytes at the address (single read primitive)."""
        return await ida_tasks.run(read_data_at_address_sync, address, size)

    @tool()
    async def get_current_address() -> Address:
        """Returns the current cursor address"""
        return await ida_tasks.run(get_current_address_sync)

    @tool()
    async def get_address_details(
        address: ty.Annotated[str, "Address to inspect"],
    ) -> AddressDetails:
        """Returns a compact summary of an address, including name and segment"""
        return await ida_tasks.run(get_address_details_sync, address)

    @tool()
    async def get_bytes(
        address: ty.Annotated[str, "Start address in hex string"],
        size: ty.Annotated[int, "Number of bytes to read"],
    ) -> str:
        """Read raw bytes from IDA database at the given address. Returns bytes as a hex string."""
        return await ida_tasks.run(get_bytes_sync, address, size)

    common_tools = [
        get_current_function,
        decompile_function,
        disassemble_function,
        get_current_address,
        get_address_details,
    ]

    exploration_tools: list[ty.Any] = [
        get_symbol_address_by_name,
        list_functions,
        list_calling_functions,
        list_called_functions,
        get_xrefs_to,
        get_xrefs_from,
        list_strings,
        list_segments,
        list_imports,
        list_exports,
        get_function_comment,
        get_local_types,
        read_data_at_address,
        get_bytes,
        search_function_comments,
    ]

    modification_tools = [
        rename_function_local_variables,
        rename_symbols,
        set_function_comments,
        set_function_prototypes,
    ]

    # Only register Swift tools if this is a Swift binary
    if await ida_tasks.run(is_swift_binary_sync):

        @tool()
        async def get_swift_source(
            address: ty.Annotated[
                str,
                "Address of the function to get Swift source for",
            ],
        ) -> str:
            """Returns the decompiled Swift source code of the given function"""
            return await ida_tasks.run(get_swift_source_sync, model, address)

        @tool()
        async def search_swift_functions(
            regex: ty.Annotated[
                str,
                "Regular expression pattern to search for in Swift function source code",
            ],
            cursor: ty.Annotated[
                ty.Optional[str],
                Field(description="Optional hex address to start from"),
            ] = None,
        ) -> PagedResults[Function]:
            """Returns a paginated list of functions with Swift source code matching the given regex pattern"""
            return await ida_tasks.run(
                search_swift_functions_sync, model, regex, cursor
            )

        exploration_tools += [get_swift_source, search_swift_functions]

    return CopilotTools(
        common=common_tools,
        exploration=exploration_tools,
        modification=modification_tools,
    )
