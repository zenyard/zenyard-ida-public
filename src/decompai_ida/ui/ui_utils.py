import ida_kernwin
import typing as ty


def get_current_line_number_from_custom_viewer_twidget(
    widget: ty.Any,
) -> int:
    place, _, _ = ida_kernwin.get_custom_viewer_place(widget, False)  # type: ignore
    simple_place = ida_kernwin.place_t.as_simpleline_place_t(place)
    return simple_place.n + 1
