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
from decompai_ida.swift_utils import (
    find_latest_not_swift_inference_sync,
    find_latest_swift_function_inference_per_profile_sync,
    find_latest_swift_function_inference_sync,
)
from decompai_ida.tasks import Task, TaskContext
from decompai_ida.ui.swift_speculation_hints_hook import (
    SwiftSpeculationHintsHook,
)
from decompai_ida.ui.swift_viewer import (
    FUNC_EA_PROPERTY,
    SwiftCodeViewer,
    create_swift_viewer,
    get_swift_viewer_from_action_context,
    install_change_profile_actions,
)
from decompai_ida.ui.ui_utils import (
    get_current_line_number_from_custom_viewer_twidget,
)
from decompai_client.models.swift_function import SwiftFunction

OPEN_SWIFT_GLOW_ACTION_ID = "zenyard:open_swift_glow"
OPEN_SWIFT_GLOW_NEW_TAB_ACTION_ID = "zenyard:open_swift_glow_new_tab"
JUMP_SWIFT_GLOW_ACTION_ID = "zenyard:jump_swift_glow"
SWIFT_GLOW_TITLE = "Zenyard SwiftGlow"


class OpenSwiftActionHandler(ida_kernwin.action_handler_t):
    """Action handler for opening the swift window."""

    _swiftglow_enabled: bool
    _model: Model
    _shared_swift_viewer: ty.Optional[SwiftCodeViewer]

    def __init__(
        self,
        swiftglow_enabled: bool,
        model: Model,
    ):
        super().__init__()
        self._swiftglow_enabled = swiftglow_enabled
        self._model = model
        self._shared_swift_viewer = None

    def activate(self, ctx):  # type: ignore
        """Handle action activation - open swift glow window."""
        try:
            swift_function_inference_per_profile = (
                find_latest_swift_function_inference_per_profile_sync(
                    model=self._model,
                    address=ctx.cur_func.start_ea,
                )
            )
            if not swift_function_inference_per_profile:
                not_swift = find_latest_not_swift_inference_sync(
                    model=self._model,
                    address=ctx.cur_func.start_ea,
                )
                messages.inform_no_swift_source_code_sync(
                    reason=not_swift.reason if not_swift else None
                )
                return 1

            action_id = getattr(ctx, "action", None)
            if action_id == OPEN_SWIFT_GLOW_NEW_TAB_ACTION_ID:
                viewer = self._get_new_tab_viewer()
            else:
                viewer = self._get_reused_viewer()

            if viewer is None:
                return 1

            viewer.update_content(
                start_ea=ctx.cur_func.start_ea,
                swift_function_inference_per_profile=swift_function_inference_per_profile,
            )
            current_swift_function = viewer.current_swift_function

            vdui = ida_hexrays.get_widget_vdui(ctx.widget)
            if vdui is not None and current_swift_function is not None:
                swift_line_number = (
                    _get_swift_line_number_for_pseudocode_widget(
                        vdui, current_swift_function
                    )
                )
            else:
                swift_line_number = 1

            viewer.jump_to_swift_line(swift_line_number)
            viewer.Show()
        except Exception as e:
            logger.error(f"Error opening swift glow: {e}")
        return 1

    def update(self, ctx):  # type: ignore
        """Update action state - enable only when database is open."""
        if self._swiftglow_enabled and idaapi.get_input_file_path() is not None:
            return ida_kernwin.AST_ENABLE
        else:
            return ida_kernwin.AST_DISABLE

    def _get_reused_viewer(self) -> ty.Optional[SwiftCodeViewer]:
        viewer = self._shared_swift_viewer
        if viewer is None or not self._is_viewer_available(viewer):
            self._shared_swift_viewer = None
            viewer = create_swift_viewer(title=SWIFT_GLOW_TITLE)
            if viewer is None:
                return None
            self._shared_swift_viewer = viewer
        return viewer

    def _get_new_tab_viewer(self) -> ty.Optional[SwiftCodeViewer]:
        for index in count(1):
            title = f"{SWIFT_GLOW_TITLE}-{index}"
            if ida_kernwin.find_widget(title) is not None:
                continue

            swift_viewer = create_swift_viewer(title=title)
            if swift_viewer is None:
                return None

            return swift_viewer
        return None

    def _is_viewer_available(self, viewer: SwiftCodeViewer) -> bool:
        if viewer.GetWidget() is None:
            return False

        if ida_kernwin.find_widget(SWIFT_GLOW_TITLE) is None:
            return False

        return True


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
        swift_function = _get_swift_function_from_action_context(ctx)
        if swift_function is None:
            logger.warning(
                "Can't find SwiftFunction inference while jumping to pseudocode",
                address=address,
            )
            return

        swift_viewer = get_swift_viewer_from_action_context(ctx)
        if swift_viewer is None:
            messages.warn_cant_open_swift_pseudocode_sync()
            return

        swift_line_number = swift_viewer.get_swift_line_number()
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
            if (
                _get_func_address_from_action_context(ctx) is not None
                and _get_swift_function_from_action_context(ctx) is not None
            ):
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


def _get_swift_function_from_action_context(
    ctx,
) -> ty.Optional[SwiftFunction]:
    viewer = get_swift_viewer_from_action_context(ctx)
    if viewer is None:
        return None

    return viewer.current_swift_function


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

        async with (
            ida_tasks.install_action(
                action_id=OPEN_SWIFT_GLOW_ACTION_ID,
                label="Open SwiftGlow",
                handler=self._open_swift_action_handler,
                shortcut="Ctrl+Alt+S",
                tooltip="Open Zenyard's SwiftGlow",
            ),
            ida_tasks.install_action(
                action_id=OPEN_SWIFT_GLOW_NEW_TAB_ACTION_ID,
                label="Open SwiftGlow in New Tab",
                handler=self._open_swift_action_handler,
                shortcut="Ctrl+Alt+Shift+S",
                tooltip="Open Zenyard's SwiftGlow in a new viewer tab",
            ),
        ):
            await ida_tasks.run_ui(
                lambda: ida_kernwin.attach_action_to_menu(
                    "Zenyard/Open Copilot",
                    OPEN_SWIFT_GLOW_NEW_TAB_ACTION_ID,
                    ida_kernwin.SETMENU_APP,
                )
            )
            await ida_tasks.run_ui(
                lambda: ida_kernwin.attach_action_to_menu(
                    "Zenyard/Open Copilot",
                    OPEN_SWIFT_GLOW_ACTION_ID,
                    ida_kernwin.SETMENU_APP,
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
                    action_id=JUMP_SWIFT_GLOW_ACTION_ID,
                    label="Jump SwiftGlow",
                    handler=self._jump_to_pseudocode_action_handler,
                    shortcut="Tab",
                ),
                install_change_profile_actions(),
                ida_tasks.install_hooks(
                    SwiftCodeAvailabilityHook(self._ctx.model)
                ),
                ida_tasks.install_hooks(
                    SwiftSpeculationHintsHook(self._ctx.model)
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
    line_number = get_current_line_number_from_custom_viewer_twidget(vdui.ct)
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
