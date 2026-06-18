import typing as ty
from dataclasses import dataclass
from inspect import cleandoc
from string import Template

import ida_kernwin
import typing_extensions as tye

from decompai_client import AnalysisSource, AnalysisType, UserConfig
from decompai_client.models import (
    AnalysisAcceptedEvent,
    InitialAnalysisDismissedEvent,
)
from decompai_ida import binary, ida_tasks, logger, swift_utils
from decompai_ida.analytics_task import analytics_timestamp
from decompai_ida.preprocessing_task import PreprocessingTask
from decompai_ida.queue_revisions_task import QueueRevisionsTask
from decompai_ida.register_binary_task import BinaryExceedsSizeLimitError
from decompai_ida.tasks import ForegroundTask, Task

# Form shown when no additional analyses are available: a plain single-page
# dialog with no tabs.
_FORM_DEFINITION_BASE = cleandoc("""
    Run Zenyard Analysis

    Looks like it's your first time opening this file — Zenyard can analyze it now to save you time and effort.
    {FormChangeCb}
    <Auto-apply results when ready:{auto_apply}>
    <Allow Zenyard to improve database before uploading:{allow_preprocessing}>{chkGroup1}>
""")

# Appended to the base form when additional analyses are available, which turns
# the dialog into a tabbed form with a separate "Analysis Options" tab.
# Template uses `$name` for substitution, so the IDA `{name}` placeholders pass
# through untouched.
_ANALYSIS_OPTIONS_TAB_TEMPLATE = Template(
    cleandoc("""
        <=:General>
        Choose additional analyses to run on this binary:

        $analyses_checkboxes
        <=:Analysis Options>
    """)
)

_BINARY_INSTRUCTIONS_PROMPT = cleandoc("""
    To improve the analysis, add any details you know (source, purpose, structure, etc.) or just click OK to continue.

    Only share what you're sure about.
""")


@dataclass(frozen=True)
class _AnalysisCheckbox:
    field_name: str
    label: str
    default_checked: bool
    enabled: bool


@dataclass(frozen=True)
class _Accepted:
    automatically_save_results: bool
    allow_preprocessing: bool
    initial_swift_analysis_enabled: ty.Optional[bool]
    """
    Tri-state: `True`/`False` reflect the swift checkbox; `None` means the
    checkbox was not shown (swift not relevant for this binary/user).
    """
    struct_reconstruction_enabled: ty.Optional[bool]
    """
    Tri-state: `True`/`False` reflect the struct reconstruction checkbox;
    `None` means the checkbox was not shown (not relevant for this user).
    """


@dataclass(frozen=True)
class _Rejected:
    pass


_FormResult: tye.TypeAlias = ty.Union[_Accepted, _Rejected]


class ShowInitialQuestionsTask(ForegroundTask):
    """
    Foreground task that displays initial questions dialog and queues next task.

    This task can be called from other places to show the initial questions dialog.
    """

    def __init__(
        self,
        *,
        swift_relevant: bool,
        struct_reconstruction_relevant: bool,
    ) -> None:
        self._swift_relevant = swift_relevant
        self._struct_reconstruction_relevant = struct_reconstruction_relevant

    def merge_from(self, other):
        self._swift_relevant = other._swift_relevant
        self._struct_reconstruction_relevant = (
            other._struct_reconstruction_relevant
        )

    def _run(self):
        form_result = _show_form_sync(
            swift_relevant=self._swift_relevant,
            struct_reconstruction_relevant=self._struct_reconstruction_relevant,
        )
        logger.info("Initial questions form result", result=form_result)

        if not isinstance(form_result, _Accepted):
            self._ctx.emit_analytics_event(
                InitialAnalysisDismissedEvent(timestamp=analytics_timestamp())
            )
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
        self._ctx.model.initial_swift_analysis_enabled.set_sync(
            form_result.initial_swift_analysis_enabled
        )
        self._ctx.model.struct_reconstruction_enabled.set_sync(
            form_result.struct_reconstruction_enabled
        )
        self._ctx.model.notify_update()


class AskInitialQuestions(Task):
    """
    Confirm initial upload preferences before registering the binary.

    This background task checks if initial questions should be shown and queues
    the ShowInitialQuestionsTask foreground task if appropriate.
    """

    async def _run(self):
        user_config = await self._verify_binary_allowed()

        is_paused = await self._ctx.model.wait_for_paused_state()
        if is_paused:
            return

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

        swift_relevant = await _is_swift_relevant(
            swiftglow_enabled=bool(user_config.swiftglow_enabled),
        )
        struct_reconstruction_relevant = bool(
            user_config.struct_reconstruction_enabled
        )

        # Queue the foreground task to show the dialog
        await logger.get().ainfo("Queueing initial questions dialog")
        self._ctx.model.runtime_status.queue_foreground_task_if_not_already_queued(
            ShowInitialQuestionsTask(
                swift_relevant=swift_relevant,
                struct_reconstruction_relevant=struct_reconstruction_relevant,
            )
        )

        # We wait here for binary registration (happens after initial questions are ANSWERED!)
        # and emit an AnalysisAcceptedEvent with a binary_id (No binary id exists before binary_registration)
        # Notice Binary registration is dependant on initial questions being answered
        # TODO - ZEN-411 improve ida flow for initial questions/analysis/binary registration
        await self._ctx.model.wait_for_registration()
        binary_instructions = await self._ctx.model.binary_instructions.get()
        binary_id = self._ctx.model.binary_id.get_sync()
        assert binary_id is not None
        self._ctx.emit_analytics_event(
            AnalysisAcceptedEvent(
                timestamp=analytics_timestamp(),
                binary_id=binary_id,
                start_source=AnalysisSource.NEW_FILE_OPEN,
                analysis_type=AnalysisType.INITIAL_ANALYSIS,
                user_prompt=binary_instructions is not None,
            )
        )

    async def _verify_binary_allowed(self) -> UserConfig:
        user_config = await self._ctx.model.wait_for_user_config()
        assert user_config.max_binary_size_mb is not None
        binary_bytes = await ida_tasks.run(binary.get_size_sync)
        if binary_bytes > user_config.max_binary_size_mb * 2**20:
            raise BinaryExceedsSizeLimitError(
                max_binary_size_mb=user_config.max_binary_size_mb
            )
        return user_config


async def _is_swift_relevant(*, swiftglow_enabled: bool) -> bool:
    if not swiftglow_enabled:
        return False
    return await ida_tasks.run(swift_utils.is_swift_binary_sync)


def _show_form_sync(
    *,
    swift_relevant: bool,
    struct_reconstruction_relevant: bool,
) -> _FormResult:
    default_general_mask = 0xFFFF

    analysis_checkboxes: list[_AnalysisCheckbox] = []
    if struct_reconstruction_relevant:
        analysis_checkboxes.append(
            _AnalysisCheckbox(
                field_name="struct_reconstruction",
                label="Struct reconstruction",
                default_checked=True,
                enabled=True,
            )
        )
    if swift_relevant:
        analysis_checkboxes.append(
            _AnalysisCheckbox(
                field_name="initial_swift_analysis",
                label="Swift reconstruction",
                default_checked=True,
                enabled=True,
            )
        )

    general_checkboxes = ida_kernwin.Form.ChkGroupControl(  # type: ignore
        ("auto_apply", "allow_preprocessing"),
        default_general_mask,
    )

    disabled_fields = tuple(
        cb.field_name for cb in analysis_checkboxes if not cb.enabled
    )

    def on_form_change(fid: int) -> int:
        # fid == -1 fires once when the form is initialized.
        if fid == -1:
            for field_name in disabled_fields:
                form.EnableField(getattr(form, field_name), False)
        return 1

    controls: dict[str, ty.Any] = {
        "chkGroup1": general_checkboxes,
        "FormChangeCb": ida_kernwin.Form.FormChangeCb(on_form_change),  # type: ignore
    }

    form_definition = _FORM_DEFINITION_BASE
    # Only render the "Analysis Options" tab when there's at least one analysis
    # to offer; otherwise keep the dialog as a plain single-page form.
    if analysis_checkboxes:
        analyses_lines = list[str]()
        analyses_mask = 0
        for i, cb in enumerate(analysis_checkboxes):
            is_last = i == len(analysis_checkboxes) - 1
            group_suffix = "{chkGroup2}>" if is_last else ""
            analyses_lines.append(
                f"<{cb.label}:{{{cb.field_name}}}>{group_suffix}"
            )
            if cb.default_checked:
                analyses_mask |= 1 << i

        form_definition += "\n" + _ANALYSIS_OPTIONS_TAB_TEMPLATE.substitute(
            analyses_checkboxes="\n".join(analyses_lines),
        )
        controls["chkGroup2"] = ida_kernwin.Form.ChkGroupControl(  # type: ignore
            tuple(cb.field_name for cb in analysis_checkboxes),
            analyses_mask,
        )

    form = ida_kernwin.Form(form_definition, controls)
    try:
        form.Compile()
        result = form.Execute()

        if result != ida_kernwin.ASKBTN_YES:
            return _Rejected()

        initial_swift_analysis_enabled: ty.Optional[bool] = None
        if swift_relevant:
            initial_swift_analysis_enabled = bool(
                form.initial_swift_analysis.checked  # type: ignore
            )

        struct_reconstruction_enabled: ty.Optional[bool] = None
        if struct_reconstruction_relevant:
            struct_reconstruction_enabled = bool(
                form.struct_reconstruction.checked  # type: ignore
            )

        return _Accepted(
            automatically_save_results=form.auto_apply.checked,  # type: ignore
            allow_preprocessing=form.allow_preprocessing.checked,  # type: ignore
            initial_swift_analysis_enabled=initial_swift_analysis_enabled,
            struct_reconstruction_enabled=struct_reconstruction_enabled,
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
