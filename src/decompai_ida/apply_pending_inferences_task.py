import ida_hexrays
import ida_kernwin

from decompai_ida import ida_tasks, inferences, logger
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
        if (
            address not in self._currently_handling
            and self._has_pending_inferences(address)
        ):
            self._currently_handling.add(address)
            ida_kernwin.execute_sync(
                lambda: self._apply_for_address(address),
                ida_kernwin.MFF_WRITE | ida_kernwin.MFF_NOWAIT,
            )
        return super().func_printed(cfunc)

    def _apply_for_address(self, address: int):
        try:
            inferences.apply_pending_inferences_sync(address, model=self._model)
        except Exception as ex:
            logger.warning(
                "Error while applying pending inferences",
                address=address,
                exc_info=ex,
            )
        finally:
            self._currently_handling.remove(address)

    def _has_pending_inferences(self, address: int) -> bool:
        return (
            next(iter(self._model.pending_inferences.read_sync(address)), None)
            is not None
        )
