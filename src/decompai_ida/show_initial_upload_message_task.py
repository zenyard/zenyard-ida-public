from inspect import cleandoc

import ida_kernwin

from decompai_ida import configuration, ida_tasks
from decompai_ida.tasks import Task

_FORM = cleandoc("""
    BUTTON YES OK
    BUTTON CANCEL NONE
    Zenyard Is Now Analyzing in the Background


    The initial processing is complete. Zenyard will continue analyzing remotely in the background.

    You can safely close IDA — no need to keep it running.

    <Don’t show this message again:C>>
""")


class ShowInitialUploadMessageTask(Task):
    async def _run(self) -> None:
        if (
            not self._ctx.plugin_config.show_initial_upload_message
            or await self._ctx.model.initial_upload_complete.get()
        ):
            return

        while not await self._ctx.model.initial_upload_complete.get():
            await self._ctx.model.wait_for_update()

        await ida_tasks.run_ui(self._show_message_sync)

    def _show_message_sync(self):
        DONT_SHOW_AGAIN_FLAG = 1 << 0

        checkboxes = ida_kernwin.Form.NumericArgument(  # type: ignore
            ida_kernwin.Form.FT_UINT64, 0
        )

        ida_kernwin.ask_form(_FORM, checkboxes.arg)

        if checkboxes.value & DONT_SHOW_AGAIN_FLAG:
            configuration.update_configuration_sync(
                {"show_initial_upload_message": False}
            )
