"""
Utilities for working with lvar names.
"""

import typing as ty
from dataclasses import dataclass

import ida_hexrays
import ida_nalt
import ida_typeinf
import typing_extensions as tye

from decompai_ida import logger


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


def _parse_type_annotation(type_annotation: str) -> ida_typeinf.tinfo_t:
    tinfo = ida_typeinf.tinfo_t()
    if (
        ida_typeinf.parse_decl(
            tinfo,
            None,  # type: ignore
            f"{type_annotation};",
            ida_typeinf.PT_SIL,
        )
        is None
    ):
        raise Exception(f"Failed to parse type annotation: {type_annotation}")
    return tinfo


def _apply_func_type_data(
    address: int, func_type_data: ida_typeinf.func_type_data_t
) -> None:
    tinfo = ida_typeinf.tinfo_t()
    # Setting to TINFO_DEFINITE so the decompiler doesn't override with guessed types
    if not tinfo.create_func(func_type_data):
        raise Exception(f"Error while creating new type for {address:016x}")
    if not ida_typeinf.apply_tinfo(address, tinfo, ida_typeinf.TINFO_DEFINITE):
        raise Exception(f"Error while saving new type for {address:016x}")


def apply_parameter_type_sync(
    address: int,
    parameter_index: int,
    type_annotation: str,
):
    func_type_data = _get_func_type_data(address)
    param = func_type_data[parameter_index]  # type: ignore
    param.type = _parse_type_annotation(type_annotation)
    _apply_func_type_data(address, func_type_data)


def apply_return_type_sync(
    address: int,
    type_annotation: str,
):
    func_type_data = _get_func_type_data(address)
    func_type_data.rettype = _parse_type_annotation(type_annotation)
    _apply_func_type_data(address, func_type_data)


def apply_func_types_batch_sync(
    address: int,
    *,
    parameter_types: ty.Optional[dict[int, str]] = None,
    return_type: ty.Optional[str] = None,
) -> None:
    """
    Apply multiple type changes to a function in a single apply_tinfo call.

    Individual parse failures are logged and skipped. The remaining valid
    types are still applied.
    """
    if not parameter_types and return_type is None:
        return

    func_type_data = _get_func_type_data(address)
    any_modified = False

    if parameter_types:
        for param_index, type_annotation in parameter_types.items():
            try:
                param = func_type_data[param_index]  # type: ignore
                param.type = _parse_type_annotation(type_annotation)
                any_modified = True
            except Exception as ex:
                logger.warning(
                    "Failed to set parameter type",
                    address=address,
                    parameter_index=param_index,
                    type_annotation=type_annotation,
                    exc_info=ex,
                )

    if return_type is not None:
        try:
            func_type_data.rettype = _parse_type_annotation(return_type)
            any_modified = True
        except Exception as ex:
            logger.warning(
                "Failed to set return type",
                address=address,
                type_annotation=return_type,
                exc_info=ex,
            )

    if not any_modified:
        return

    _apply_func_type_data(address, func_type_data)


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
