from inspect import cleandoc

import ida_hexrays
import ida_kernwin
from more_itertools import partition

from decompai_client import VariablesMapping
from decompai_ida import api, inferences, logger
from decompai_ida.model import Inference
from decompai_ida.tasks import ForegroundTask

# Larger batches save more work when there are multiple inferences to same
# address, but will make UI less responsive to cancel requests.
_BATCH_SIZE = 16

_WAITBOX_TEXT = cleandoc("""
    Zenyard is applying your latest results — almost done
""")

# Types of inferences to just queue as pending, to be applied when function is
# shown to user. This should include inferences that are not visible outside
# decompiled code, and that are slow to apply (e.g. require decompilation).
_INFERENCE_TYPES_TO_DEFER: set[type[Inference]] = {
    VariablesMapping,
}


class ApplyInferencesTask(ForegroundTask):
    """
    Foreground task which applies all queued inferences.
    """

    def _run(self):
        inference_count = self._ctx.model.inference_queue.size_sync()
        if inference_count == 0:
            return

        logger.debug("Applying inferences", count=inference_count)
        self._wait_box.start_new_task(_WAITBOX_TEXT, items=inference_count)

        while self._ctx.model.inference_queue.size_sync() > 0:
            batch = self._ctx.model.inference_queue.peek_sync(_BATCH_SIZE)

            supported_inferences = (
                inference for inference in batch if inference is not None
            )
            immediate, deferred = partition(
                lambda inference: type(inference) in _INFERENCE_TYPES_TO_DEFER,
                supported_inferences,
            )

            # Apply immediate inferences
            inferences.apply_inferences_sync(
                (inference for inference in immediate if inference is not None),
                model=self._ctx.model,
            )

            # Queue deferred inferences
            for deferred_inference in deferred:
                address = api.parse_address(deferred_inference.address)
                self._ctx.model.pending_inferences.push_sync(
                    address, deferred_inference
                )

            self._ctx.model.inference_queue.pop_sync(_BATCH_SIZE)
            self._wait_box.mark_items_complete(len(batch))
            self._ctx.model.notify_update()

        # Update visible decompiled code, in case it has pending inferences.
        _update_pseudocode_viewer()


def _update_pseudocode_viewer():
    current_vdui = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_viewer())

    if current_vdui is None:
        return

    if not current_vdui.visible():
        return

    current_vdui.refresh_view(True)
