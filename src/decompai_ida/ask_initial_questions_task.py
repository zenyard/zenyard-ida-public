import typing as ty
from dataclasses import dataclass
from inspect import cleandoc

import ida_kernwin
import typing_extensions as tye

from decompai_ida import logger
from decompai_ida.preprocessing_task import PreprocessingTask
from decompai_ida.queue_revisions_task import QueueRevisionsTask
from decompai_ida.tasks import ForegroundTask, Task

_FORM_DEFINITION = cleandoc("""
    Run Zenyard Analysis

    Looks like it's your first time opening this file — Zenyard can analyze it now to save you time and effort.

    <Auto-apply results when ready:{auto_apply}>
    <Allow Zenyard to improve database before uploading:{allow_preprocessing}>{chkGroup1}>
""")

_BINARY_INSTRUCTIONS_PROMPT = cleandoc("""
    To improve the analysis, add any details you know (source, purpose, structure, etc.) or just click OK to continue.

    Only share what you're sure about.
""")


@dataclass(frozen=True)
class _Accepted:
    automatically_save_results: bool
    allow_preprocessing: bool


@dataclass(frozen=True)
class _Rejected:
    pass


_FormResult: tye.TypeAlias = ty.Union[_Accepted, _Rejected]


class ShowInitialQuestionsTask(ForegroundTask):
    """
    Foreground task that displays initial questions dialog and queues next task.

    This task can be called from other places to show the initial questions dialog.
    """

    def _run(self):
        form_result = _show_form_sync()
        logger.info("Initial questions form result", result=form_result)

        if not isinstance(form_result, _Accepted):
            return

        # Mark as asked only if the user accepted
        self._ctx.model.asked_initial_questions.set_sync(True)

        binary_instructions: ty.Optional[str] = None
        if self._ctx.plugin_config.request_binary_instructions:
            binary_instructions = _ask_for_binary_instructions_sync()

        if form_result.automatically_save_results:
            self._ctx.model.runtime_status.apply_inferences_when_ready = True

        if form_result.allow_preprocessing:
            self._ctx.model.runtime_status.queue_foreground_task_if_not_already_queued(
                PreprocessingTask()
            )
        else:
            # Preprocessing skipped, ready for upload
            self._ctx.model.ready_for_analysis.set_sync(True)
        self._ctx.model.runtime_status.queue_foreground_task_if_not_already_queued(
            QueueRevisionsTask()
        )

        # Save binary instructions
        self._ctx.model.binary_instructions.set_sync(binary_instructions)
        self._ctx.model.notify_update()


class AskInitialQuestions(Task):
    """
    Confirm initial upload preferences before registering the binary.

    This background task checks if initial questions should be shown and queues
    the ShowInitialQuestionsTask foreground task if appropriate.
    """

    async def _run(self):
        already_asked = await self._ctx.model.asked_initial_questions.get()
        already_uploaded = await self._ctx.model.initial_upload_complete.get()

        if already_asked or already_uploaded:
            await logger.get().adebug(
                "Skipping initial questions",
                already_asked=already_asked,
                already_uploaded=already_uploaded,
            )
            await self._ctx.model.ready_for_analysis.set(True)
            self._ctx.model.notify_update()
            return

        # Queue the foreground task to show the dialog
        await logger.get().ainfo("Queueing initial questions dialog")
        self._ctx.model.runtime_status.queue_foreground_task_if_not_already_queued(
            ShowInitialQuestionsTask()
        )


def _show_form_sync() -> _FormResult:
    checkboxes = ida_kernwin.Form.ChkGroupControl(  # type: ignore
        ("auto_apply", "allow_preprocessing"),
        # Auto check all
        0xFFFF,
    )
    form = ida_kernwin.Form(_FORM_DEFINITION, {"chkGroup1": checkboxes})
    try:
        form.Compile()
        result = form.Execute()

        if result != ida_kernwin.ASKBTN_YES:
            return _Rejected()

        return _Accepted(
            automatically_save_results=form.auto_apply.checked,  # type: ignore
            allow_preprocessing=form.allow_preprocessing.checked,  # type: ignore
        )
    finally:
        form.Free()


def _ask_for_binary_instructions_sync() -> ty.Optional[str]:
    """Ask user for binary instructions (synchronous, for use in ForegroundTask)."""
    result = ida_kernwin.ask_text(
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
