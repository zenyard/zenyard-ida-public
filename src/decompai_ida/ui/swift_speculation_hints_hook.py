from dataclasses import dataclass
from datetime import timedelta
import time
import typing as ty
import ida_kernwin
from textwrap import wrap

from decompai_client import SwiftFunction
from decompai_ida.model import Model
from decompai_ida.swift_utils import (
    NumberedSpeculation,
    NumberedSpeculationsPerLine,
    build_speculations_per_line,
    format_speculation_marker,
    speculation_marker_width,
)
from decompai_ida.ui.swift_viewer import FUNC_EA_PROPERTY

_CACHE_EXPIRATION = timedelta(seconds=30)


@dataclass(frozen=True, kw_only=True)
class _CachedSpeculations:
    address: int
    cached_at: float
    speculations: NumberedSpeculationsPerLine

    @staticmethod
    def empty() -> "_CachedSpeculations":
        return _CachedSpeculations(address=0, cached_at=0, speculations={})

    @staticmethod
    def create(
        *, address: int, speculations: NumberedSpeculationsPerLine
    ) -> "_CachedSpeculations":
        return _CachedSpeculations(
            address=address,
            cached_at=time.monotonic(),
            speculations=speculations,
        )

    def is_valid_for_address(self, address: int) -> bool:
        return address == self.address and (
            (time.monotonic() - self.cached_at)
            < _CACHE_EXPIRATION.total_seconds()
        )


def _render_speculation_text(numbered_speculation: NumberedSpeculation) -> str:
    return format_speculation_marker(numbered_speculation) + "\n".join(
        wrap(
            numbered_speculation.speculation.description,
            initial_indent=" ",
            subsequent_indent=(
                " " * speculation_marker_width(numbered_speculation)
            ),
        )
    )


class SwiftSpeculationHintsHook(ida_kernwin.UI_Hooks):
    def __init__(self, model: Model):
        super().__init__()
        self._model = model
        self._cached_inference = _CachedSpeculations.empty()

    def get_custom_viewer_hint(self, viewer, place, /):
        speculations = self._get_speculations_for_widget(viewer)
        if speculations is None:
            return super().get_custom_viewer_hint(viewer, place)

        line_place = ida_kernwin.place_t.as_simpleline_place_t(place)
        if line_place is None:
            return

        line_speculations = speculations.get(line_place.n + 1, ())
        if len(line_speculations) == 0:
            return super().get_custom_viewer_hint(viewer, place)

        text = "\n\n".join(
            _render_speculation_text(speculation)
            for speculation in line_speculations
        ).strip()

        text_lines = text.count("\n") + 1

        is_trivial = all(
            speculation.speculation.is_trivial
            for speculation in line_speculations
        )
        caption = "Notes" if is_trivial else "Speculated code"

        return (
            f"CAPTION {caption}\n{text}",
            text_lines + 1,
        )

    def _get_speculations_for_widget(
        self, widget: ty.Any
    ) -> ty.Optional[NumberedSpeculationsPerLine]:
        address = ida_kernwin.PluginForm.TWidgetToPyQtWidget(widget).property(
            FUNC_EA_PROPERTY
        )
        if address is None:
            # Not a SwiftViewer
            return

        if not self._cached_inference.is_valid_for_address(address):
            result = next(
                (
                    inference
                    for inference in self._model.inferences.read_sync(address)
                    if isinstance(inference, SwiftFunction)
                ),
                None,
            )

            self._cached_inference = _CachedSpeculations.create(
                address=address,
                speculations=build_speculations_per_line(result)
                if result is not None
                else {},
            )

        return self._cached_inference.speculations
