"""
Utilities for working with lvar names.
"""

import typing as ty
from dataclasses import dataclass

import ida_hexrays
import ida_nalt
import ida_typeinf
import typing_extensions as tye


@dataclass(frozen=True)
class Name:
    name: str
    "Name as shown in decompiler output"

    is_dummy: bool
    "Is this a dummy name (e.g. `a1`, `v1`)."


def get_parameter_names_sync(address: int) -> list[Name]:
    func_type_data = _get_func_type_data(address)

    return [
        Name(
            name=arg.name if arg.name != "" else f"a{i}",
            is_dummy=arg.name == "",
        )
        for i, arg in enumerate(func_type_data, 1)  # type: ignore
    ]


def apply_parameter_renames_sync(address: int, renames: ty.Mapping[int, str]):
    if len(renames) == 0:
        return

    func_type_data = _get_func_type_data(address)
    for rename_index, rename_to in renames.items():
        func_type_data[rename_index].name = rename_to  # type: ignore

    tinfo = ida_typeinf.tinfo_t()
    success = tinfo.create_func(func_type_data)
    if not success:
        raise Exception(f"Error while creating new type for {address:016x}")

    success = ida_nalt.set_tinfo(address, tinfo)
    if not success:
        raise Exception(f"Error while saving new type for {address:016x}")


def apply_parameter_type_sync(
    address: int,
    parameter_index: int,
    type_annotation: str,
):
    func_type_data = _get_func_type_data(address)

    # Parse the type annotation into a tinfo_t
    type_tinfo = ida_typeinf.tinfo_t()
    parse_result = ida_typeinf.parse_decl(
        type_tinfo,
        None,  # type: ignore
        f"{type_annotation} a;",
        ida_typeinf.PT_SIL,
    )
    if parse_result is None:
        raise Exception(f"Failed to parse type annotation: {type_annotation}")

    # Set the parameter type
    func_type_data[parameter_index].type = type_tinfo  # type: ignore

    # Create and save the new function type
    tinfo = ida_typeinf.tinfo_t()
    success = tinfo.create_func(func_type_data)
    if not success:
        raise Exception(f"Error while creating new type for {address:016x}")

    # Setting to TINFO_DEFINITE due to the decompiler overriding guessed types
    success = ida_typeinf.apply_tinfo(
        address, tinfo, ida_typeinf.TINFO_DEFINITE
    )
    if not success:
        raise Exception(f"Error while saving new type for {address:016x}")


def apply_return_type_sync(
    address: int,
    type_annotation: str,
):
    """Apply a return type annotation to a function.

    Args:
        address: Function address
        type_annotation: C type string (e.g., "int", "void*", "MyStruct*")
    """
    func_type_data = _get_func_type_data(address)

    # Parse the type annotation into a tinfo_t
    type_tinfo = ida_typeinf.tinfo_t()
    parse_result = ida_typeinf.parse_decl(
        type_tinfo,
        None,  # type: ignore
        f"{type_annotation} a;",
        ida_typeinf.PT_SIL,
    )
    if parse_result is None:
        raise Exception(f"Failed to parse type annotation: {type_annotation}")

    # Set the return type (KEY DIFFERENCE from parameter type)
    func_type_data.rettype = type_tinfo

    # Create and save the new function type
    tinfo = ida_typeinf.tinfo_t()
    success = tinfo.create_func(func_type_data)
    if not success:
        raise Exception(f"Error while creating new type for {address:016x}")

    # Setting to TINFO_DEFINITE due to the decompiler overriding guessed types
    success = ida_typeinf.apply_tinfo(
        address, tinfo, ida_typeinf.TINFO_DEFINITE
    )
    if not success:
        raise Exception(f"Error while saving new type for {address:016x}")


_CFunc: tye.TypeAlias = ty.Union[ida_hexrays.cfunc_t, ida_hexrays.cfuncptr_t]


def get_variable_names_sync(func: _CFunc) -> list[Name]:
    user_lvar_settings = ida_hexrays.lvar_uservec_t()
    ida_hexrays.restore_user_lvar_settings(user_lvar_settings, func.entry_ea)  # type: ignore
    named_lvars = {
        lvar_setting.name for lvar_setting in user_lvar_settings.lvvec
    }

    return [
        Name(name=lvar.name, is_dummy=lvar.name not in named_lvars)
        for lvar in func.lvars  # type: ignore
        if not lvar.is_arg_var
    ]


def apply_variable_renames_sync(func: _CFunc, renames: ty.Mapping[str, str]):
    address = func.entry_ea  # type: ignore
    user_lvar_settings = ida_hexrays.lvar_uservec_t()
    ida_hexrays.restore_user_lvar_settings(user_lvar_settings, address)

    lvar_name_to_lvar_info = {lv.name: lv for lv in user_lvar_settings.lvvec}
    lvar_name_to_lvar = {
        lv.name: lv
        for lv in func.lvars  # type: ignore
        if not lv.is_arg_var
    }

    for rename_from, rename_to in renames.items():
        lvar_saved_info = lvar_name_to_lvar_info.get(rename_from)
        if lvar_saved_info is not None:
            lvar_saved_info.name = rename_to
        else:
            lvar_saved_info = ida_hexrays.lvar_saved_info_t()
            lvar = lvar_name_to_lvar.get(rename_from)
            if lvar is None:
                continue
            lvar_saved_info.ll = lvar
            lvar_saved_info.name = rename_to
            user_lvar_settings.lvvec.append(lvar_saved_info)

    ida_hexrays.save_user_lvar_settings(address, user_lvar_settings)
    ida_hexrays.mark_cfunc_dirty(address)


def _get_func_type_data(address: int) -> ida_typeinf.func_type_data_t:
    tinfo = ida_typeinf.tinfo_t()
    success = ida_nalt.get_tinfo(tinfo, address)
    if not success:
        raise Exception(f"Can't read type info at {address:016x}")

    if not tinfo.is_func():
        raise Exception(f"Not a function at {address:016x}")

    func_type_data = ida_typeinf.func_type_data_t()
    success = tinfo.get_func_details(func_type_data)
    if not success:
        raise Exception(f"Can't get function type data at {address:016x}")

    return func_type_data
