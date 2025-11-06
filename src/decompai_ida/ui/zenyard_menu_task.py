import ida_kernwin

from decompai_ida import ida_tasks
from decompai_ida.async_utils import (
    wait_for_object_of_type,
)
from decompai_ida.events import DatabaseClosed, DatabaseOpened
from decompai_ida.tasks import GlobalTask

PLACEHOLDER_ACTION_ID = "zenyard:menu_placeholder"


class PlaceholderActionHandler(ida_kernwin.action_handler_t):
    """Action handler for the placeholder action when no database is open."""

    def activate(self, ctx):  # type: ignore
        """Handle action activation - does nothing since it's always disabled."""
        return 1

    def update(self, ctx):  # type: ignore
        """Update action state - always disabled."""
        return ida_kernwin.AST_DISABLE


class ZenyardMenuTask(GlobalTask):
    """
    Global task that manages the Zenyard menu and placeholder action.
    Creates the menu on startup and shows/hides placeholder based on database state.
    """

    async def _run(self) -> None:
        """Main task execution - set up menu and manage placeholder visibility."""
        # Create menu and placeholder action handler
        placeholder_handler = PlaceholderActionHandler()

        # Create menu if it doesn't exist
        await ida_tasks.run_ui(
            lambda: ida_kernwin.create_menu("zenyard", "&Zenyard", "Help")
        )

        # Subscribe to database events
        async with self._ctx.ida_events.subscribe() as event_receiver:
            # Show placeholder initially (no database open on startup)
            async with ida_tasks.install_action(
                action_id=PLACEHOLDER_ACTION_ID,
                label="Open a database to start...",
                handler=placeholder_handler,
            ):
                await ida_tasks.run_ui(
                    lambda: ida_kernwin.attach_action_to_menu(
                        "Zenyard",
                        PLACEHOLDER_ACTION_ID,
                        0,
                    )
                )

                while True:
                    # Wait for database to open
                    await wait_for_object_of_type(
                        event_receiver, DatabaseOpened
                    )

                    # Hide placeholder by detaching from menu
                    await ida_tasks.run_ui(
                        lambda: ida_kernwin.detach_action_from_menu(
                            "Zenyard",
                            PLACEHOLDER_ACTION_ID,
                        )
                    )

                    # Wait for database to close
                    await wait_for_object_of_type(
                        event_receiver, DatabaseClosed
                    )

                    # Show placeholder again by reattaching to menu
                    await ida_tasks.run_ui(
                        lambda: ida_kernwin.attach_action_to_menu(
                            "Zenyard",
                            PLACEHOLDER_ACTION_ID,
                            0,
                        )
                    )
