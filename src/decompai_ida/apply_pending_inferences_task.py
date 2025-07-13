import ida_hexrays

from decompai_ida import ida_tasks, inferences
from decompai_ida.async_utils import wait_until_cancelled
from decompai_ida.model import Model
from decompai_ida.tasks import Task


class ApplyPendingInferencesTask(Task):
    async def _run(self) -> None:
        async with ida_tasks.install_hooks(
            _ApplyPendingInferencesHooks(self._ctx.model)
        ):
            await wait_until_cancelled()


class _ApplyPendingInferencesHooks(ida_hexrays.Hexrays_Hooks):
    def __init__(self, model: Model):
        super().__init__()
        self._model = model
        self._currently_handling = set[int]()

    def func_printed(self, cfunc, /) -> "int":
        # Note that applying non empty list of inferences will cause func to be
        # printed again. We make sure not to handle the second event to avoid
        # recursion loop.

        address = cfunc.entry_ea
        if address not in self._currently_handling:
            self._currently_handling.add(address)
            try:
                inferences.apply_pending_inferences_sync(
                    cfunc.entry_ea, model=self._model
                )
            finally:
                self._currently_handling.remove(address)
        return super().func_printed(cfunc)
