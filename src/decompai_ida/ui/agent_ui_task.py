import ida_kernwin

from decompai_ida import ida_tasks, logger
from decompai_ida.async_utils import wait_until_cancelled
from decompai_ida.model import Model
from decompai_ida.tasks import Task
from decompai_ida.web_ui import WebUI

OPEN_AGENT_ACTION_ID = "zenyard:open_agent"


class OpenAgentActionHandler(ida_kernwin.action_handler_t):
    """Opens the Zenyard Agent web chat."""

    def __init__(self, *, web_ui: WebUI, model: Model):
        super().__init__()
        self._web_ui = web_ui
        self._model = model

    def activate(self, ctx):  # type: ignore
        try:
            self._web_ui.open_new_agent()
        except Exception as e:
            logger.error(f"Error opening Zenyard Agent: {e}")
        return 1

    def update(self, ctx):  # type: ignore
        if self._model.runtime_status.relay_identity is not None:
            return ida_kernwin.AST_ENABLE
        return ida_kernwin.AST_DISABLE


class AgentUiTask(Task):
    """Installs the menu action + shortcut that opens the Zenyard Agent."""

    async def _run(self) -> None:
        async with ida_tasks.install_action(
            action_id=OPEN_AGENT_ACTION_ID,
            label="Zenyard Agent",
            handler=OpenAgentActionHandler(
                web_ui=self._ctx.web_ui, model=self._ctx.model
            ),
            shortcut="Ctrl+Alt+C",
            tooltip="Open the Zenyard Agent",
        ):
            await ida_tasks.run_ui(
                lambda: ida_kernwin.attach_action_to_menu(
                    "Zenyard/Zenyard Agent",
                    OPEN_AGENT_ACTION_ID,
                    0,
                )
            )
            await wait_until_cancelled()
