from dataclasses import dataclass
import re
import typing as ty

import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_name
import ida_typeinf
import idaapi
import idautils

from pydantic import Field
from decompai_ida import ida_tasks
from decompai_ida.model import Model
from decompai_ida.swift_utils import (
    find_latest_swift_function_inference_sync,
    is_swift_binary_sync,
)
from itertools import dropwhile, islice
from langchain.tools import tool

Address = ty.Annotated[str, "The address in hex string"]

_SymbolName: ty.TypeAlias = ty.Annotated[
    str,
    "Symbol name to resolve to an address. Can be a function name or a global variable name.",
]


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
        raise Exception(f"Failed to retreive function from address: {address}")
    return func


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


def rename_function_local_variable_sync(
    address: str, from_name: str, to_name: str
):
    func = get_function(address)
    ida_hexrays.rename_lvar(func.start_ea, from_name, to_name)
    # TODO: We probably want to do it only once in a while
    _update_pseudocode_viewer()


def rename_symbol_sync(address: str, new_name: str):
    if not ida_name.set_name(int(address, 16), new_name):
        raise Exception(f"Failed to rename {address} to {new_name}")
    _update_pseudocode_viewer()


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


def set_function_comment_sync(address: str, comment: ty.Optional[str]):
    func = get_function(address)
    ida_funcs.set_func_cmt(func, comment or "", False)
    _update_pseudocode_viewer()


def set_function_prototype_sync(address: str, new_prototype: str):
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
    _update_pseudocode_viewer()


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
    async def rename_function_local_variable(
        address: ty.Annotated[
            str,
            "Address of the function to rename a local variable in",
        ],
        from_name: ty.Annotated[
            str,
            "The original name of the variable to rename",
        ],
        to_name: ty.Annotated[str, "The new name of the variable"],
    ):
        """Rename a local variable in the given function"""
        return await ida_tasks.run(
            rename_function_local_variable_sync, address, from_name, to_name
        )

    @tool()
    async def rename_symbol(
        symbol_address: _SymbolName,
        new_name: ty.Annotated[str, "The new name for the symbol."],
    ):
        """Renames a symbol such as a function or a global variable"""
        # TODO: Consider using from_name, to_name to lower chance of hallucinations
        return await ida_tasks.run(rename_symbol_sync, symbol_address, new_name)

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
    async def get_function_comment(
        address: ty.Annotated[str, "Address of the function"],
    ) -> ty.Optional[str]:
        """Returns the function documentation for the given function"""
        return await ida_tasks.run(get_function_comment_sync, address)

    @tool()
    async def set_function_comment(
        address: ty.Annotated[str, "Address of the function"],
        comment: ty.Annotated[
            ty.Optional[str],
            "The new function documentation or None to remove the current one. "
            "Use 80 character lines and format this like a function documentation.",
        ],
    ) -> ty.Optional[str]:
        """Sets the function documentation for the given function"""
        return await ida_tasks.run(set_function_comment_sync, address, comment)

    @tool()
    async def set_function_prototype(
        address: ty.Annotated[str, "Address of the function"],
        new_prototype: ty.Annotated[
            str, "A new c-style function prototype for the function"
        ],
    ):
        """Sets a function's prototype"""
        return await ida_tasks.run(
            set_function_prototype_sync, address, new_prototype
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

    copilot_tools = [
        get_current_function,
        get_symbol_address_by_name,
        list_functions,
        decompile_function,
        rename_function_local_variable,
        rename_symbol,
        list_calling_functions,
        get_function_comment,
        set_function_comment,
        set_function_prototype,
        get_local_types,
        search_function_comments,
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

        copilot_tools += [get_swift_source, search_swift_functions]

    return copilot_tools
