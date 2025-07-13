import ida_funcs
import idc

from decompai_ida import ida_tasks, inferences, logger
from decompai_ida.events import AddressModified
from decompai_ida.tasks import Task


class ClearInferenceMarksTask(Task):
    async def _run(self) -> None:
        async with self._ctx.ida_events.subscribe() as event:
            if isinstance(event, AddressModified):
                await ida_tasks.run(
                    self._clear_inferred_name_marks_sync, event.address
                )

    def _clear_inferred_name_marks_sync(self, address: int):
        log = logger.bind(address=address)

        func = ida_funcs.get_func(address)
        if func is None or address != func.start_ea:
            log.debug("Not clearing mark, not a function")
            return

        if idc.get_color(address, idc.CIC_FUNC) != inferences.INFERRED_COLOR:
            log.debug("Mark not detected")
            return

        if not inferences.has_user_defined_name_sync(
            address, model=self._ctx.model
        ):
            log.debug("Not clearing mark - name is not set by user")
            return

        log.info("Clearing inference mark", address=address)
        idc.set_color(address, idc.CIC_FUNC, idc.DEFCOLOR)
