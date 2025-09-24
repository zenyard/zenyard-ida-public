import ida_kernwin

from decompai_ida import ida_tasks
from decompai_ida.async_utils import wait_until_cancelled
from decompai_ida.inferences import has_user_defined_name_sync
from decompai_ida.model import Model
from decompai_ida.tasks import Task, TaskContext
from decompai_client import SwiftFunction, Name


def _rgb_to_int(r: int, g: int, b: int) -> int:
    return (b << 16) + (g << 8) + r


INFERRED_COLOR = _rgb_to_int(220, 202, 255)
SWIFT_INFERRED_COLOR = _rgb_to_int(243, 105, 55)


class FunctionsColorizerHook(ida_kernwin.UI_Hooks):
    _model: Model

    def __init__(
        self,
        model: Model,
    ):
        super().__init__()
        self._model = model

    def get_chooser_item_attrs(self, chobj, n, attrs):
        ea = chobj.get_ea(n)
        inferences = list(self._model.inferences.read_sync(ea))
        has_name_inferences = False
        has_swift_inferences = False
        for inference in inferences:
            if isinstance(inference, SwiftFunction):
                has_swift_inferences = True
                break
            elif isinstance(inference, Name):
                has_name_inferences = True

        if has_swift_inferences:
            attrs.color = SWIFT_INFERRED_COLOR
        elif has_name_inferences and (
            not has_user_defined_name_sync(ea, model=self._model)
        ):
            attrs.color = INFERRED_COLOR

    def preprocess_action(self, name):
        self._current_action_name = name
        return 0

    def postprocess_action(self):
        if self._current_action_name == "OpenFunctions":
            # Necessary to receive chooser item updates
            ida_kernwin.enable_chooser_item_attrs("Functions", True)
        return 0


class FunctionsColorizerTask(Task):
    """
    Task that manages the functions chooser coloring.
    """

    def __init__(self, task_context: TaskContext):
        super().__init__(task_context)

    async def _run(self) -> None:
        async with ida_tasks.install_hooks(
            FunctionsColorizerHook(self._ctx.model)
        ):
            await ida_tasks.run_ui(
                ida_kernwin.enable_chooser_item_attrs, "Functions", True
            )
            await wait_until_cancelled()
