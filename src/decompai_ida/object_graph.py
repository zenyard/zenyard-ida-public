import graphlib
import typing as ty

from decompai_ida.objects import Symbol
import ida_funcs
import idautils
import typing_extensions as tye
from more_itertools import side_effect

from decompai_ida.wait_box import check_user_cancelled

_AddressGraph: tye.TypeAlias = ty.Mapping[int, ty.Collection[int]]


def get_objects_in_approx_topo_order_sync(
    symbols: ty.Iterable[Symbol],
) -> ty.Sequence[int]:
    """
    Returns given functions in approximate topological order.

    Each given address must be that starting address of a function.
    """
    symbols = list(symbols)
    obj_to_dependencies = {symbol.address: set() for symbol in symbols}

    for caller, callee in _read_calls(
        symbol.address for symbol in symbols if symbol.type == "function"
    ):
        if caller in obj_to_dependencies:
            obj_to_dependencies[caller].add(callee)

    for global_variable_address, function_address in _read_xrefs_from_functions(
        symbol.address for symbol in symbols if symbol.type == "global_variable"
    ):
        if global_variable_address in obj_to_dependencies:
            obj_to_dependencies[global_variable_address].add(function_address)

    return _approx_topo_order(obj_to_dependencies)


def _read_calls(
    target_addresses: ty.Iterable[int],
) -> ty.Iterator[tuple[int, int]]:
    for target_address in target_addresses:
        for code_ref in idautils.CodeRefsTo(target_address, flow=False):
            from_func = ida_funcs.get_func(code_ref)
            if from_func is not None:
                yield (from_func.start_ea, target_address)


def _read_xrefs_from_functions(
    target_addresses: ty.Iterable[int],
) -> ty.Iterator[tuple[int, int]]:
    for target_address in target_addresses:
        for xref in idautils.XrefsTo(target_address):
            accessing_function = ida_funcs.get_func(xref.frm)  # type: ignore
            if accessing_function is not None:
                yield (target_address, accessing_function.start_ea)


def _approx_topo_order(graph: _AddressGraph) -> ty.Sequence[int]:
    """
    Returns an approximate topological ordering of nodes in graph, given
    by mapping between node to its dependencies (predecessors).

    If cycles exist in graph, arbitrary edges would be ignored.
    """

    g = {node: set(deps) for node, deps in graph.items()}

    while True:
        try:
            return list(
                side_effect(
                    lambda _: check_user_cancelled(),
                    graphlib.TopologicalSorter(g).static_order(),
                )
            )
        except graphlib.CycleError as e:
            cycle = e.args[1]
            dep = cycle[0]
            node = cycle[1]
            assert dep in g[node]
            g[node].remove(dep)
