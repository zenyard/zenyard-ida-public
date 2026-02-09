import ida_funcs
import ida_kernwin

from decompai_ida import ida_tasks
from decompai_ida.async_utils import wait_until_cancelled
from decompai_ida.model import AddressUserOptions, Model
from decompai_ida.queue_swift_revisions_task import QueueSwiftRevisionsTask
from decompai_ida.tasks import Task

ACTION_ID = "zenyard:analyze_as_swift"

_SHOW_IN_WIDGETS = (
    ida_kernwin.BWN_FUNCS,
    ida_kernwin.BWN_DISASMS,
    ida_kernwin.BWN_PSEUDOCODE,
)


class _AnalyzeAsSwiftHandler(ida_kernwin.action_handler_t):
    def __init__(self, model: Model):
        super().__init__()
        self._model = model

    def _mark_functions_for_swift_analysis_sync(
        self, addresses: list[int]
    ) -> None:
        # Mark objects as forced-Swift for current and future uploads.
        for address in addresses:
            options = (
                self._model.address_user_options.get_sync(address)
                or AddressUserOptions()
            )
            if options.analyze_as_swift:
                continue
            self._model.address_user_options.set_sync(
                address, options.with_analyze_as_swift(True)
            )

        # Immediately queue Swift-focused revisions
        self._model.runtime_status.queue_foreground_task_if_not_already_queued(
            QueueSwiftRevisionsTask(addresses)
        )
        self._model.notify_update()

    def activate(self, ctx):  # type: ignore
        funcs = list[int]()

        # Case 1: We are in the Functions Window (BWN_FUNCS)
        if ctx.widget_type == ida_kernwin.BWN_FUNCS and ctx.chooser_selection:
            for func_index in ctx.chooser_selection:
                func = ida_funcs.getn_func(func_index)
                if func:
                    funcs.append(func.start_ea)

        # Case 2: We are in Disassembly (BWN_DISASMS) or Decompiler (BWN_PSEUDOCODE)
        elif ctx.widget_type in (
            ida_kernwin.BWN_DISASMS,
            ida_kernwin.BWN_PSEUDOCODE,
        ):
            func = ida_funcs.get_func(ctx.cur_ea)
            if func:
                funcs.append(func.start_ea)

        self._mark_functions_for_swift_analysis_sync(funcs)

        return 1

    def update(self, ctx):  # type: ignore
        if ctx.widget_type in _SHOW_IN_WIDGETS:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class _FunctionsPopupHook(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):  # type: ignore
        if ida_kernwin.get_widget_type(widget) in _SHOW_IN_WIDGETS:
            ida_kernwin.attach_action_to_popup(widget, None, ACTION_ID, "")


class AnalyzeAsSwiftTask(Task):
    async def _run(self) -> None:
        async with (
            ida_tasks.install_action(
                action_id=ACTION_ID,
                label="Analyze as Swift",
                handler=_AnalyzeAsSwiftHandler(self._ctx.model),
            ),
            ida_tasks.install_hooks(_FunctionsPopupHook()),
        ):
            await wait_until_cancelled()
