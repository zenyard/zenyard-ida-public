import typing as ty
from dataclasses import dataclass
from inspect import cleandoc

import ida_kernwin
import typing_extensions as tye

from decompai_ida import ida_tasks, logger
from decompai_ida.queue_revisions_task import QueueRevisionsTask
from decompai_ida.tasks import Task

_FORM_DEFINITION = cleandoc("""
    Run Zenyard Analysis



    Looks like it’s your first time opening this file — Zenyard can analyze it now to save you time and effort.

    <Auto-apply results when ready:C>>
""")
_AUTOMATICALLY_SAVE_RESULTS_FLAG = 1 << 0


@dataclass(frozen=True)
class _Accepted:
    automatically_save_results: bool


@dataclass(frozen=True)
class _Rejected:
    pass


_FormResult: tye.TypeAlias = ty.Union[_Accepted, _Rejected]


class TriggerInitialUploadTask(Task):
    """
    Offers user to perform initial upload - queues `QueueRevisionsTask` and sets
    `apply_inferences_when_ready`.
    """

    async def _run(self):
        # Wait for registration to ensure user and binary are allowed before
        # showing anything to user.
        await self._ctx.model.wait_for_registration()

        if await self._ctx.model.initial_upload_complete.get():
            await logger.get().adebug(
                "Not suggesting initial upload - already uploaded"
            )
            return

        if self._ctx.plugin_config.require_confirmation_per_db:
            if not await self._ctx.model.initial_upload_suggested.get():
                form_result = await ida_tasks.run(_show_form_sync)
                await self._ctx.model.initial_upload_suggested.set(True)
                await logger.get().ainfo(
                    "Suggested initial upload", result=form_result
                )
            else:
                await logger.get().adebug(
                    "Not suggesting initial upload - already suggested"
                )
                form_result = _Rejected()
        else:
            await logger.get().ainfo(
                "Automatically triggering initial upload as configured"
            )
            form_result = _Accepted(automatically_save_results=True)

        if isinstance(form_result, _Accepted):
            self._ctx.model.runtime_status.queue_foreground_task_if_not_already_queued(
                QueueRevisionsTask
            )

            if form_result.automatically_save_results:
                self._ctx.model.runtime_status.apply_inferences_when_ready = (
                    True
                )

            self._ctx.model.notify_update()


def _show_form_sync() -> _FormResult:
    checkboxes = ida_kernwin.Form.NumericArgument(  # type: ignore
        ida_kernwin.Form.FT_UINT64,
        _AUTOMATICALLY_SAVE_RESULTS_FLAG,
    )
    result = ida_kernwin.ask_form(_FORM_DEFINITION, checkboxes.arg)

    if result != ida_kernwin.ASKBTN_YES:
        return _Rejected()

    return _Accepted(
        automatically_save_results=(
            checkboxes.value & _AUTOMATICALLY_SAVE_RESULTS_FLAG
        )
    )
