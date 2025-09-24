from dataclasses import dataclass
from itertools import count
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_moves
import idaapi
import typing as ty


from decompai_client import LineMapping
from decompai_ida import ida_tasks, logger, messages, lines
from decompai_ida.async_utils import wait_until_cancelled
from decompai_ida.model import Model
from decompai_ida.swift_utils import find_latest_swift_function_inference_sync
from decompai_ida.tasks import Task, TaskContext
from decompai_ida.ui.swift_viewer import FUNC_EA_PROPERTY, create_swift_viewer
from decompai_client.models.swift_function import SwiftFunction

OPEN_SWIFT_GLOW_ACTION_ID = "zenyard:open_swift_glow"
JUMP_SWIFT_GLOW_ACTION_ID = "zenyard:jump_swift_glow"


class OpenSwiftActionHandler(ida_kernwin.action_handler_t):
    """Action handler for opening the swift window."""

    _swiftglow_enabled: bool
    _model: Model

    def __init__(
        self,
        swiftglow_enabled: bool,
        model: Model,
    ):
        super().__init__()
        self._swiftglow_enabled = swiftglow_enabled
        self._model = model

    def activate(self, ctx):  # type: ignore
        """Handle action activation - open swift glow window."""
        try:
            swift_function = find_latest_swift_function_inference_sync(
                self._model,
                ctx.cur_func.start_ea,
            )
            if swift_function is None:
                messages.inform_no_swift_source_code_sync()
                return 1

            vdui = ida_hexrays.get_widget_vdui(ctx.widget)
            if vdui is not None:
                swift_line_number = (
                    _get_swift_line_number_for_pseudocode_widget(
                        vdui, swift_function
                    )
                )
            else:
                swift_line_number = 1

            for i in count(1):
                swift_viewer = create_swift_viewer(
                    ctx.cur_func.start_ea,
                    swift_function.source,
                    title=f"Swift-{i}",
                )
                if swift_viewer is not None:
                    swift_viewer.Jump(swift_line_number - 1, 0, 0)
                    swift_viewer.Show()
                    break
        except Exception as e:
            logger.error(f"Error opening swift glow: {e}")
        return 1

    def update(self, ctx):  # type: ignore
        """Update action state - enable only when database is open."""
        if self._swiftglow_enabled and idaapi.get_input_file_path() is not None:
            return ida_kernwin.AST_ENABLE
        else:
            return ida_kernwin.AST_DISABLE


class JumpToPseudocodeActionHandler(ida_kernwin.action_handler_t):
    """Action handler for jumping from swift code to pseudocode."""

    def __init__(self, model: Model):
        super().__init__()
        self._model = model

    def activate(self, ctx):  # type: ignore
        address = _get_func_address_from_action_context(ctx)
        if address is None:
            messages.warn_cant_open_swift_pseudocode_sync()
            return

        vdui = ida_hexrays.open_pseudocode(address, ida_hexrays.OPF_REUSE)
        if vdui is None:
            messages.warn_cant_open_swift_pseudocode_sync()
            return

        cfunc: ida_hexrays.cfunc_t = vdui.cfunc
        swift_function = find_latest_swift_function_inference_sync(
            self._model, address
        )
        if swift_function is None:
            logger.warning(
                "Can't find SwiftFunction inference while jumping to pseudocode",
                address=address,
            )
            return

        swift_line_number = _get_current_line_number_from_custom_viewer_twidget(
            ctx.widget
        )
        line_mappings = _translate_mappings_to_line_numbers(
            cfunc=cfunc, line_mappings=swift_function.line_mappings
        )
        pseudocode_line_number = (
            _find_pseudocode_line_number_for_swift_line_number(
                swift_line_number=swift_line_number, line_mappings=line_mappings
            )
        )
        _jump_to_pseudocode_line_number(vdui, pseudocode_line_number)

    def update(self, ctx):  # type: ignore
        """Update action state - enable only when database is open."""
        if idaapi.get_input_file_path() is not None:
            if _get_func_address_from_action_context(ctx) is not None:
                return ida_kernwin.AST_ENABLE_FOR_WIDGET
            else:
                return ida_kernwin.AST_DISABLE_FOR_WIDGET
        else:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET


def _get_func_address_from_action_context(ctx) -> ty.Optional[int]:
    """Extract function address from action context widget property."""
    if ctx.widget is None:
        return None
    return ida_kernwin.PluginForm.TWidgetToPyQtWidget(ctx.widget).property(
        FUNC_EA_PROPERTY
    )


class SwiftCodeAvailabilityHook(ida_kernwin.UI_Hooks):
    def __init__(
        self,
        model: Model,
    ):
        super().__init__()
        self._model = model

    def current_widget_changed(self, _widget, _prev_widget):
        ida_kernwin.request_refresh(ida_kernwin.IWID_DISASM)

    def screen_ea_changed(self, ea, _prev_ea):
        update_swift_code_availability_for_ea_sync(self._model, ea)


def update_swift_code_availability_for_ea_sync(model: Model, ea: int):
    func = ida_funcs.get_func(ea)
    model.swift_source_available = (
        func is not None
    ) and find_latest_swift_function_inference_sync(
        model, func.start_ea
    ) is not None
    model.notify_update()


def update_swift_code_availability_sync(model: Model):
    update_swift_code_availability_for_ea_sync(
        model, ida_kernwin.get_screen_ea()
    )


class SwiftUiTask(Task):
    """
    Task that manages the swift glow UI components.
    """

    def __init__(self, task_context: TaskContext):
        super().__init__(task_context)
        self._open_swift_action_handler: ty.Optional[OpenSwiftActionHandler] = (
            None
        )
        self._jump_to_pseudocode_action_handler: ty.Optional[
            JumpToPseudocodeActionHandler
        ] = None

    async def _run(self) -> None:
        user_config = await self._ctx.model.wait_for_user_config()

        swiftglow_enabled = bool(user_config.swiftglow_enabled)

        # Create action handlers
        self._open_swift_action_handler = OpenSwiftActionHandler(
            swiftglow_enabled, self._ctx.model
        )

        async with ida_tasks.install_action(
            OPEN_SWIFT_GLOW_ACTION_ID,
            "Open Swift Glow",
            self._open_swift_action_handler,
            "Ctrl+Alt+S",
            "Open Zenyard's Swift Glow",
        ):
            # Attach to menu
            await ida_tasks.run_ui(
                lambda: ida_kernwin.attach_action_to_menu(
                    "Zenyard", OPEN_SWIFT_GLOW_ACTION_ID, 0
                )
            )

            # No need for the action and hook below if SwiftGlow is not enabled
            if not swiftglow_enabled:
                await wait_until_cancelled()
                return

            self._jump_to_pseudocode_action_handler = (
                JumpToPseudocodeActionHandler(self._ctx.model)
            )

            await ida_tasks.run_ui(
                update_swift_code_availability_sync, self._ctx.model
            )

            async with (
                ida_tasks.install_action(
                    JUMP_SWIFT_GLOW_ACTION_ID,
                    "Jump Swift Glow",
                    self._jump_to_pseudocode_action_handler,
                    "Tab",
                ),
                ida_tasks.install_hooks(
                    SwiftCodeAvailabilityHook(self._ctx.model)
                ),
            ):
                await wait_until_cancelled()


@dataclass(frozen=True, kw_only=True)
class _LineNumberMapping:
    first_inferred_line: int
    first_input_line_number: int
    last_input_line_number: int

    @property
    def line_count(self) -> int:
        return self.last_input_line_number - self.first_input_line_number + 1

    def contains(self, line_number: int) -> bool:
        return (
            self.first_input_line_number
            <= line_number
            <= self.last_input_line_number
        )


def _translate_mappings_to_line_numbers(
    cfunc: ida_hexrays.cfunc_t,
    line_mappings: ty.Iterable[LineMapping],
) -> ty.Iterable[_LineNumberMapping]:
    line_id_to_number = dict[str, int]()

    for i, line_id in enumerate(lines.get_line_ids(cfunc)):
        if line_id not in line_id_to_number:
            line_id_to_number[line_id] = i + 1

    for line_mapping in line_mappings:
        first_input_line_number = line_id_to_number.get(
            line_mapping.first_input_line_id
        )
        last_input_line_number = line_id_to_number.get(
            line_mapping.last_input_line_id
        )
        if (
            first_input_line_number is not None
            and last_input_line_number is not None
        ):
            yield _LineNumberMapping(
                first_inferred_line=line_mapping.first_inferred_line,
                first_input_line_number=first_input_line_number,
                last_input_line_number=last_input_line_number,
            )


def _find_pseudocode_line_number_for_swift_line_number(
    swift_line_number: int,
    line_mappings: ty.Iterable[_LineNumberMapping],
) -> int:
    preceding_mappings = (
        mapping
        for mapping in line_mappings
        if mapping.first_inferred_line <= swift_line_number
    )

    nearest_mapping = max(
        preceding_mappings,
        key=lambda mapping: mapping.first_inferred_line,
        default=None,
    )

    return (
        nearest_mapping.first_input_line_number
        if nearest_mapping is not None
        else 1
    )


def _jump_to_pseudocode_line_number(
    widget: ida_hexrays.vdui_t, line_number: int
):
    location = ida_kernwin.listing_location_t()
    ida_kernwin.get_custom_viewer_location(location, widget.ct, 0)
    line_place = ida_kernwin.place_t.as_simpleline_place_t(location.loc.place())  # type: ignore
    line_place.n = line_number - 1
    entry = ida_moves.lochist_entry_t(line_place, location.loc.renderer_info())  # type: ignore
    ida_kernwin.custom_viewer_jump(widget.ct, entry)


def _get_swift_line_number_for_pseudocode_widget(
    vdui: ida_hexrays.vdui_t,
    swift_function: SwiftFunction,
) -> int:
    line_number = _get_current_line_number_from_custom_viewer_twidget(vdui.ct)
    line_mappings = _translate_mappings_to_line_numbers(
        vdui.cfunc, swift_function.line_mappings
    )
    containing_mappings = (
        line_mapping
        for line_mapping in line_mappings
        if line_mapping.contains(line_number)
    )
    smallest_mapping = min(
        containing_mappings,
        key=lambda mapping: mapping.line_count,
        default=None,
    )
    return (
        smallest_mapping.first_inferred_line
        if smallest_mapping is not None
        else 1
    )


def _get_current_line_number_from_custom_viewer_twidget(widget) -> int:
    place, _, _ = ida_kernwin.get_custom_viewer_place(widget, False)  # type: ignore
    simple_place = ida_kernwin.place_t.as_simpleline_place_t(place)
    return simple_place.n + 1
