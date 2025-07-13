import typing as ty
from collections import defaultdict

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_name
import idc
import structlog
import typing_extensions as tye

from decompai_client import (
    FunctionOverview,
    Name,
    ParametersMapping,
    VariablesMapping,
)
from decompai_ida import api, logger, markdown
from decompai_ida.events import block_ida_events
from decompai_ida.lvars import (
    apply_parameter_renames_sync,
    apply_variable_renames_sync,
    get_parameter_names_sync,
    get_variable_names_sync,
)
from decompai_ida.model import Inference, Model


def _rgb_to_int(r: int, g: int, b: int) -> int:
    return (b << 16) + (g << 8) + r


INFERRED_COLOR = _rgb_to_int(220, 202, 255)


def apply_pending_inferences_sync(address: int, *, model: Model):
    pending_inferences = list(model.pending_inferences.read_sync(address))
    # Reverse the list to get oldest to newest.
    pending_inferences = pending_inferences[::-1]
    if len(pending_inferences) > 0:
        _apply_inferences_for_address(address, pending_inferences, model=model)
        model.pending_inferences.clear_address_sync(address)


def apply_inferences_sync(inferences: ty.Iterable[Inference], *, model: Model):
    by_address = defaultdict[int, list[Inference]](list)
    for inference in inferences:
        by_address[api.parse_address(inference.address)].append(inference)

    for address, inferences in by_address.items():
        _apply_inferences_for_address(address, inferences, model=model)


def _apply_inferences_for_address(
    address: int,
    inferences: ty.Collection[Inference],
    *,
    model: Model,
):
    with (
        structlog.contextvars.bound_contextvars(address=address),
        block_ida_events(),
    ):
        logger.debug("Applying inferences on address", count=len(inferences))
        for inference in inferences:
            try:
                inference = _apply_local_transformations(inference)
                assert api.parse_address(inference.address) == address

                if isinstance(inference, FunctionOverview):
                    _apply_overview(inference, model=model)
                elif isinstance(inference, Name):
                    _apply_name(inference, model=model)
                elif isinstance(inference, ParametersMapping):
                    _apply_parameters(inference, model=model)
                elif isinstance(inference, VariablesMapping):
                    _apply_variables(inference, model=model)
                else:
                    _: tye.Never = inference

                model.inferences.push_sync(address, inference)

            except Exception as ex:
                logger.warning("Error while applying inferences", exc_info=ex)

    _update_pseudocode_viewer_for_address(address)


def _update_pseudocode_viewer_for_address(address: int):
    current_vdui = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_viewer())

    if current_vdui is None:
        return

    if not current_vdui.visible():
        return

    if current_vdui.cfunc is None:
        return

    if current_vdui.cfunc.entry_ea != address:
        return

    current_vdui.refresh_view(True)


def has_user_defined_name_sync(address: int, *, model: Model) -> bool:
    """
    Whether given address was named by user (i.e. not inferred or unnamed).
    """

    name = ida_name.get_name(address)
    if not ida_name.is_uname(name):
        # Unnamed.
        return False

    return not any(
        isinstance(inference, Name) and inference.name in name
        for inference in model.inferences.read_sync(address)
    )


def has_user_defined_comment_sync(address: int, *, model: Model) -> bool:
    """
    Whether given address has function comment given by user.
    """

    func = ida_funcs.get_func(address)
    if func is None:
        return False

    comment = ida_funcs.get_func_cmt(func, False) or ida_funcs.get_func_cmt(
        func, True
    )
    if comment is None:
        return False

    comment = comment.strip()
    if len(comment) == 0:
        return False

    return not any(
        isinstance(inference, FunctionOverview)
        and inference.full_description.strip() == comment
        for inference in model.inferences.read_sync(address)
    )


T = ty.TypeVar("T")


def _get_last_inference_type(
    address: int,
    inference_type: ty.Type[T],
    *,
    model: Model,
) -> ty.Union[T, None]:
    return next(
        (
            inference
            for inference in model.inferences.read_sync(address)
            if isinstance(inference, inference_type)
        ),
        None,
    )


def _apply_local_transformations(inference: Inference) -> Inference:
    if isinstance(inference, FunctionOverview):
        overview = inference
        return overview.model_copy(
            update={
                "full_description": markdown.format(overview.full_description)
            }
        )
    else:
        return inference


def _apply_overview(overview: FunctionOverview, *, model: Model):
    address = api.parse_address(overview.address)

    if has_user_defined_comment_sync(address, model=model):
        return

    func = ida_funcs.get_func(address)
    assert func is not None

    ida_funcs.set_func_cmt(func, overview.full_description, False)


def _apply_name(name: Name, *, model: Model):
    address = api.parse_address(name.address)

    if has_user_defined_name_sync(address, model=model):
        return

    # Add leading underscore to avoid reserved prefix (e.g. `byte_`).
    name_to_apply = (
        name.name if ida_name.is_uname(name.name) else f"_{name.name}"
    )

    address_flags = ida_bytes.get_full_flags(address)
    if ida_bytes.is_data(address_flags) or ida_bytes.is_unknown(address_flags):
        ida_name.set_name(address, name_to_apply, ida_name.SN_FORCE)
    else:
        func = ida_funcs.get_func(address)
        assert func is not None
        is_thunk = bool(func.flags & ida_funcs.FUNC_THUNK)

        if is_thunk:
            # Let IDA manage names of thunks
            return

        ida_name.set_name(address, name_to_apply, ida_name.SN_FORCE)
        idc.set_color(address, idc.CIC_FUNC, INFERRED_COLOR)


def _apply_variables(variables_mapping: VariablesMapping, *, model: Model):
    address = api.parse_address(variables_mapping.address)
    func = ida_funcs.get_func(address)
    assert func is not None

    failure = ida_hexrays.hexrays_failure_t()
    decompiled = ida_hexrays.decompile_func(
        func,
        failure,
        ida_hexrays.DECOMP_NO_WAIT,
    )
    if decompiled is None:
        raise Exception(f"Can't decompile: {failure.desc()}")

    variable_names = get_variable_names_sync(decompiled)
    # TODO: Not sure if to use last or merge
    last_variables_mapping = _get_last_inference_type(
        address, VariablesMapping, model=model
    )
    last_inferred_variable_names = set()
    if last_variables_mapping is not None:
        last_inferred_variable_names = set(
            last_variables_mapping.variables_mapping.values()
        )
    variable_name_to_variable_name_obj = {
        variable_name.name: variable_name for variable_name in variable_names
    }
    renames = {}
    for original_variable_name in variables_mapping.variables_mapping:
        variable_name = variable_name_to_variable_name_obj.get(
            original_variable_name
        )
        if variable_name is None:
            continue
        if not variable_name.is_dummy:
            if variable_name.name in last_inferred_variable_names:
                # Only override user defined variables that were inferred
                renames[original_variable_name] = (
                    variables_mapping.variables_mapping[original_variable_name]
                )
        else:
            renames[original_variable_name] = (
                variables_mapping.variables_mapping[original_variable_name]
            )

    apply_variable_renames_sync(decompiled, renames)


def _apply_parameters(parameters_mapping: ParametersMapping, *, model: Model):
    address = api.parse_address(parameters_mapping.address)
    parameter_names = get_parameter_names_sync(address)
    # TODO: Not sure if to use last or merge
    last_parameters_mapping = _get_last_inference_type(
        address,
        ParametersMapping,
        model=model,
    )
    last_inferred_parameter_names = set()
    if last_parameters_mapping is not None:
        last_inferred_parameter_names = set(
            last_parameters_mapping.parameters_mapping.values()
        )

    renames = {}
    for parameter_index, parameter_name in enumerate(parameter_names):
        if (
            not parameter_name.is_dummy
            and parameter_name.name not in last_inferred_parameter_names
        ):
            # Skip user defined parameter names
            continue
        new_name = parameters_mapping.parameters_mapping.get(
            parameter_name.name
        )
        if new_name is not None:
            renames[parameter_index] = new_name
    apply_parameter_renames_sync(address, renames)
