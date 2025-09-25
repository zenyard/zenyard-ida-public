import typing as ty
from dataclasses import dataclass
from inspect import cleandoc

import anyio
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

_BINARY_INSTRUCTIONS_PROMPT = cleandoc("""
    To improve the analysis, add any details you know (source, purpose, structure, etc.) or just click OK to continue.

    Only share what you’re sure about.
""")


@dataclass(frozen=True)
class _Accepted:
    automatically_save_results: bool


@dataclass(frozen=True)
class _Rejected:
    pass


_FormResult: tye.TypeAlias = ty.Union[_Accepted, _Rejected]


class AskInitialQuestions(Task):
    """Confirm initial upload preferences before registering the binary."""

    async def _run(self):
        binary_instructions: ty.Optional[str] = None
        already_asked = await self._ctx.model.asked_initial_questions.get()

        try:
            if await self._ctx.model.initial_upload_complete.get():
                await logger.get().adebug(
                    "Not suggesting initial upload - already uploaded"
                )
                return

            if already_asked:
                await logger.get().adebug(
                    "Not suggesting initial upload - already suggested"
                )
                return

            if self._ctx.plugin_config.require_confirmation_per_db:
                form_result = await ida_tasks.run(_show_form_sync)
                await logger.get().ainfo(
                    "Suggested initial upload", result=form_result
                )
            else:
                await logger.get().ainfo(
                    "Automatically triggering initial upload as configured"
                )
                form_result = _Accepted(automatically_save_results=True)

            if isinstance(form_result, _Accepted):
                if self._ctx.plugin_config.request_binary_instructions:
                    binary_instructions = await _ask_for_binary_instructions()

                self._ctx.model.runtime_status.queue_foreground_task_if_not_already_queued(
                    QueueRevisionsTask
                )

                if form_result.automatically_save_results:
                    self._ctx.model.runtime_status.apply_inferences_when_ready = True

                self._ctx.model.notify_update()
        finally:
            with anyio.CancelScope(shield=True):
                await self._ctx.model.binary_instructions.set(
                    binary_instructions
                )
                await self._ctx.model.asked_initial_questions.set(True)


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


async def _ask_for_binary_instructions() -> ty.Optional[str]:
    result = await ida_tasks.run(
        ida_kernwin.ask_text,
        10_000,
        "",
        _BINARY_INSTRUCTIONS_PROMPT,
    )
    if result is None:
        return None

    result = result.strip()
    if result == "":
        return None

    return result
