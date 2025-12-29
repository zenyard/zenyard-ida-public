import ida_kernwin
from textwrap import wrap

from decompai_ida.model import Model
from decompai_ida.swift_utils import (
    NumberedSpeculation,
    format_speculation_marker,
    speculation_marker_width,
)
from decompai_ida.ui.swift_viewer import SWIFT_VIEWER_PROPERTY, SwiftCodeViewer


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

    def get_custom_viewer_hint(self, viewer, place, /):
        swift_viewer = ida_kernwin.PluginForm.TWidgetToPyQtWidget(
            viewer
        ).property(SWIFT_VIEWER_PROPERTY)
        if not isinstance(swift_viewer, SwiftCodeViewer):
            return super().get_custom_viewer_hint(viewer, place)

        line_speculations = swift_viewer.get_speculations_for_place(place)
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
