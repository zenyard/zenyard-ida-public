import anyio
import ida_kernwin
import idaapi
import typing as ty

from decompai_ida import ida_tasks, logger
from decompai_ida.tasks import Task, TaskContext
from decompai_ida.ui.copilot import CopilotWindow, CopilotViewModel

OPEN_COPILOT_ACTION_ID = "zenyard:open_copilot"
ZENYARD_COPILOT_TAB_NAME = "Zenyard Copilot"


class OpenCopilotActionHandler(ida_kernwin.action_handler_t):
    """Action handler for opening the copilot window."""

    def __init__(self, ui_task: "CopilotUiTask"):
        super().__init__()
        self._ui_task = ui_task

    def activate(self, ctx):  # type: ignore
        """Handle action activation - open copilot window."""
        try:
            self._ui_task.open_copilot_window()
        except Exception as e:
            logger.error(f"Error opening copilot: {e}")
        return 1

    def update(self, ctx):  # type: ignore
        """Update action state - enable only when database is open."""
        if idaapi.get_input_file_path() is not None:
            return ida_kernwin.AST_ENABLE
        else:
            return ida_kernwin.AST_DISABLE


class CopilotUiTask(Task):
    """
    Task that manages the copilot UI components.
    Creates and wires together CopilotWindow and CopilotViewModel.
    """

    def __init__(self, task_context: TaskContext):
        super().__init__(task_context)
        self._view_model: ty.Optional[CopilotViewModel] = None
        self._current_window: ty.Optional[CopilotWindow] = None
        self._action_handler: ty.Optional[OpenCopilotActionHandler] = None

    async def _run(self) -> None:
        """Main task execution - set up UI components and handle model updates."""
        user_config = await self._ctx.model.wait_for_user_config()
        if user_config.copilot is None:
            return

        # Create view model
        self._view_model = CopilotViewModel(self._ctx.copilot_model)

        # Register action handler
        await self._register_action_handler()

        # Main loop: update view model when copilot model changes
        while True:
            with anyio.move_on_after(1):
                await self._ctx.copilot_model.wait_for_update()
            if self._view_model is not None:
                self._view_model.update_from_model()

    async def _register_action_handler(self) -> None:
        """Register the copilot action handler in the UI thread."""

        def register_action():
            try:
                # Create action handler
                self._action_handler = OpenCopilotActionHandler(self)

                # Create menu if it doesn't exist
                ida_kernwin.create_menu("zenyard", "&Zenyard", "Help")

                # Unregister the action first to ensure previous action handlers are not called
                ida_kernwin.unregister_action(OPEN_COPILOT_ACTION_ID)

                # Register action
                ida_kernwin.register_action(
                    ida_kernwin.action_desc_t(
                        OPEN_COPILOT_ACTION_ID,
                        "Open Copilot",
                        self._action_handler,
                        "Ctrl+Alt+C",
                        "Open Zenyard's Copilot",
                    )
                )

                # Attach to menu
                ida_kernwin.attach_action_to_menu(
                    "Zenyard/Open Copilot", OPEN_COPILOT_ACTION_ID, 0
                )

                logger.debug("Copilot action handler registered successfully")

            except Exception as e:
                logger.error(f"Error registering copilot action: {e}")

        await ida_tasks.run_ui(register_action)

    def open_copilot_window(self) -> None:
        """Open the copilot window or focus if already open."""
        try:
            if ida_kernwin.find_widget(ZENYARD_COPILOT_TAB_NAME) is None:
                # Create new window
                if self._view_model is None:
                    logger.error("View model not initialized")
                    return

                self._current_window = CopilotWindow(self._view_model)
                self._current_window.Show(ZENYARD_COPILOT_TAB_NAME)

                # Position the window
                ida_kernwin.set_dock_pos(
                    ZENYARD_COPILOT_TAB_NAME, "Output", ida_kernwin.DP_RIGHT
                )

                # Set focus
                self._current_window.input_focus()

                logger.debug("Copilot window created successfully")
            else:
                # Window already exists, just focus it
                if self._current_window is not None:
                    self._current_window.input_focus()

        except Exception as e:
            logger.error(f"Error opening copilot window: {e}")
