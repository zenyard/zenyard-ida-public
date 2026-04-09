from contextlib import asynccontextmanager
from functools import cache
import typing as ty
import typing_extensions as tye
from itertools import chain
import ida_kernwin
import ida_lines
import importlib.resources
from qtpy import QtGui
from qtpy.QtWidgets import QWidget

from decompai_client import SwiftFunction, TranslationProfile
from decompai_ida import assets, ida_tasks
from decompai_ida import logger
from decompai_ida.swift_utils import (
    NumberedSpeculation,
    NumberedSpeculationsPerLine,
    build_speculations_per_line,
    format_speculation_marker,
)
from decompai_ida.ui.swift_highlighter import (
    SwiftHighlighter,
    SwiftTokenType,
    HighlightedToken,
)
from decompai_ida.ui.ui_utils import (
    get_current_line_number_from_custom_viewer_twidget,
)

FUNC_EA_PROPERTY = "start_ea"
SWIFT_VIEWER_PROPERTY = "swift_viewer"
_SYNTHETIC_LINE_COUNT = 1

_PROFILE_LABEL_PER_TRANSLATION_PROFILE: dict[TranslationProfile, str] = {
    TranslationProfile.BALANCED: "balanced",
    TranslationProfile.CONSERVATIVE: "conservative",
    TranslationProfile.RISKY: "speculative",
}

# When wanted profile is missing, will select first available in this order.
# First profile will be used by default for new views.
_PROFILE_PREFERENCE_ORDER = [
    TranslationProfile.BALANCED,
    TranslationProfile.CONSERVATIVE,
    TranslationProfile.RISKY,
]

# Action IDs for popup menu
CHANGE_TO_CONSERVATIVE_PROFILE_ACTION = "zenyard:swift_profile:conservative"
CHANGE_TO_BALANCED_PROFILE_ACTION = "zenyard:swift_profile:balanced"
CHANGE_TO_RISKY_PROFILE_ACTION = "zenyard:swift_profile:speculative"


class ChangeTransformProfileActionHandler(ida_kernwin.action_handler_t):
    """Base action handler for transformation profile level selection."""

    def __init__(self, profile: TranslationProfile):
        super().__init__()
        self._profile = profile

    def activate(self, ctx):  # type: ignore
        swift_viewer = get_swift_viewer_from_action_context(ctx)
        if swift_viewer is None:
            # Unexpected
            return 1

        swift_viewer.set_transformation_profile(self._profile)
        return 1

    def update(self, ctx):  # type: ignore
        swift_viewer = get_swift_viewer_from_action_context(ctx)
        if swift_viewer is None:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET

        if not swift_viewer.supports_profile(self._profile):
            return ida_kernwin.AST_DISABLE_FOR_WIDGET

        return ida_kernwin.AST_ENABLE_FOR_WIDGET


_conservative_handler = ChangeTransformProfileActionHandler(
    TranslationProfile.CONSERVATIVE
)
_balanced_handler = ChangeTransformProfileActionHandler(
    TranslationProfile.BALANCED
)
_risky_handler = ChangeTransformProfileActionHandler(TranslationProfile.RISKY)


def _label_for_change_profile_action(profile: TranslationProfile) -> str:
    profile_label = _PROFILE_LABEL_PER_TRANSLATION_PROFILE[profile]
    return f"Switch to {profile_label} profile"


@asynccontextmanager
async def install_change_profile_actions():
    async with (
        ida_tasks.install_action(
            action_id=CHANGE_TO_CONSERVATIVE_PROFILE_ACTION,
            label=_label_for_change_profile_action(
                TranslationProfile.CONSERVATIVE
            ),
            handler=_conservative_handler,
            shortcut="1",
        ),
        ida_tasks.install_action(
            action_id=CHANGE_TO_BALANCED_PROFILE_ACTION,
            label=_label_for_change_profile_action(TranslationProfile.BALANCED),
            handler=_balanced_handler,
            shortcut="2",
        ),
        ida_tasks.install_action(
            action_id=CHANGE_TO_RISKY_PROFILE_ACTION,
            label=_label_for_change_profile_action(TranslationProfile.RISKY),
            handler=_risky_handler,
            shortcut="3",
        ),
    ):
        yield


class SwiftCodeViewer(ida_kernwin.simplecustviewer_t):
    """
    Swift code viewer widget using IDA's simplecustviewer_t with syntax highlighting.

    This widget displays Swift source code with syntax highlighting provided by
    Pygments. Call :meth:`update_content` to populate the viewer with Swift code
    and associated metadata.
    """

    def __init__(
        self,
    ) -> None:
        """Initialize the Swift code viewer."""
        super().__init__()
        self._start_ea: ty.Optional[int] = None
        self._current_profile: TranslationProfile = _PROFILE_PREFERENCE_ORDER[0]
        self._swift_function_inference_per_profile: ty.Mapping[
            TranslationProfile, SwiftFunction
        ] = {}
        self._speculations: NumberedSpeculationsPerLine = {}
        self._highlighter = SwiftHighlighter()

    @property
    def current_swift_function(self) -> ty.Optional[SwiftFunction]:
        return self._swift_function_inference_per_profile.get(
            self._current_profile
        )

    def supports_profile(self, profile: TranslationProfile) -> bool:
        return profile in self._swift_function_inference_per_profile

    def Create(self, title: str) -> bool:  # type: ignore
        """
        Create and show the Swift code viewer window.

        Args:
            title: Optional title override

        Returns:
            True if creation was successful
        """
        try:
            # Create the viewer
            if not super().Create(title):
                logger.error("Failed to create simplecustviewer_t")
                return False

            created_widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(
                self.GetWidget()
            )
            _setup_tab_icon(created_widget)

            created_widget.setProperty(SWIFT_VIEWER_PROPERTY, self)
            if self._start_ea is not None:
                created_widget.setProperty(FUNC_EA_PROPERTY, self._start_ea)

            # Register and attach popup menu actions
            widget = self.GetWidget()
            if widget is not None:
                ida_kernwin.attach_action_to_popup(
                    widget,
                    None,
                    CHANGE_TO_CONSERVATIVE_PROFILE_ACTION,
                    "",
                )
                ida_kernwin.attach_action_to_popup(
                    widget,
                    None,
                    CHANGE_TO_BALANCED_PROFILE_ACTION,
                    "",
                )
                ida_kernwin.attach_action_to_popup(
                    widget,
                    None,
                    CHANGE_TO_RISKY_PROFILE_ACTION,
                    "",
                )

            logger.debug(f"Swift code viewer created: {title}")
            return True

        except Exception as e:
            logger.error(f"Error creating Swift code viewer: {e}")
            return False

    def _add_highlighted_content(self) -> None:
        """Add the Swift code content with syntax highlighting to the viewer."""
        swift_function = self.current_swift_function
        source = swift_function.source if swift_function is not None else ""
        try:
            if not source:
                self.AddLine("No Swift code provided", ida_lines.SCOLOR_ERROR)
                return

            profile_label = _PROFILE_LABEL_PER_TRANSLATION_PROFILE[
                self._current_profile
            ]
            source = f"// Profile: {profile_label}\n{source}"

            # Split code into lines, add synthetic lines
            lines = source.splitlines(keepends=True)

            highlighted_tokens = self._highlighter.highlight(source)
            next_highlighted_token = []

            # Add lines with highlighting
            line_start = 0

            for display_line_number, line in enumerate(lines, start=1):
                line_end = line_start + len(line)

                # Get tokens for this line
                line_tokens = []
                for token in chain(next_highlighted_token, highlighted_tokens):
                    if (
                        token.start_byte >= line_start
                        and token.start_byte < line_end
                    ):
                        line_tokens.append(token)
                    else:
                        next_highlighted_token = [token]
                        break

                # Create highlighted line
                line_postfix = self._get_line_postfix(display_line_number)
                highlighted_line = self._create_highlighted_line(
                    line, line_tokens
                )
                self.AddLine(highlighted_line + line_postfix)

                # Move to next line
                line_start = line_end

        except Exception as e:
            logger.error(f"Error adding highlighted content: {e}")
            # Fallback to plain text
            self.ClearLines()
            for line in source.splitlines():
                self.AddLine(line)

    def _get_line_postfix(self, display_line_number: int) -> str:
        swift_line_number = _to_swift_line_number(display_line_number)
        if swift_line_number is None:
            return ""

        speculations = self._speculations.get(swift_line_number, ())

        if len(speculations) == 0:
            return ""

        postfix = "".join(
            format_speculation_marker(speculation)
            for speculation in speculations
        )

        return "  " + postfix

    def _create_highlighted_line(
        self, line: str, line_tokens: ty.List[HighlightedToken]
    ) -> str:
        """
        Create a highlighted line using IDA's color codes.

        Args:
            line: The original line text
            tokens: Tokens that belong to this line
            line_start: Starting byte position of this line in the full code

        Returns:
            Line with IDA color codes embedded
        """
        try:
            # Sort tokens by position within the line
            result = ""

            for token in line_tokens:
                # Add the highlighted token
                color_code = self._get_ida_color_code(token.token_type)
                if color_code:
                    result += f"{ida_lines.COLSTR(token.text, color_code)}"
                else:
                    result += token.text

            return result

        except Exception as e:
            logger.error(f"Error creating highlighted line: {e}")
            return line  # Return original line on error

    def _get_ida_color_code(self, token_type: SwiftTokenType) -> int:
        """
        Get IDA color code for a token type.

        Args:
            token_type: The Swift token type

        Returns:
            IDA color code string or empty string if no special color
        """
        # Map Swift token types to IDA color codes, sampled from the pseudocode tokens
        match token_type:
            case SwiftTokenType.KEYWORD:
                return ida_lines.SCOLOR_KEYWORD
            case SwiftTokenType.STRING:
                return ida_lines.SCOLOR_DSTR
            case SwiftTokenType.COMMENT:
                return ida_lines.SCOLOR_NUMBER
            case SwiftTokenType.NUMBER:
                return ida_lines.SCOLOR_KEYWORD
            case SwiftTokenType.FUNCTION:
                return ida_lines.SCOLOR_LIBNAME
            case SwiftTokenType.TYPE:
                return ida_lines.SCOLOR_DNAME
            case SwiftTokenType.ATTRIBUTE:
                return ida_lines.SCOLOR_MACRO
            case SwiftTokenType.IDENTIFIER:
                return ida_lines.SCOLOR_LIBNAME
            case SwiftTokenType.OPERATOR:
                return ida_lines.SCOLOR_DNAME
            case SwiftTokenType.PUNCTUATION:
                return ida_lines.SCOLOR_DNAME
            case SwiftTokenType.DEFAULT:
                return ida_lines.SCOLOR_DNAME
            case _:
                _: tye.Never = token_type

    def update_content(
        self,
        *,
        start_ea: int,
        swift_function_inference_per_profile: ty.Mapping[
            TranslationProfile, SwiftFunction
        ],
    ) -> None:
        """Replace the displayed Swift content and metadata."""

        self._start_ea = start_ea
        self._swift_function_inference_per_profile = dict(
            swift_function_inference_per_profile
        )
        self._refresh_current_function()

    def set_transformation_profile(self, profile: TranslationProfile):
        self._current_profile = profile
        self._refresh_current_function()

    def _refresh_current_function(self):
        try:
            # If profile missing, switch select by preference
            if self.current_swift_function is None:
                for profile in self._swift_function_inference_per_profile:
                    if self.supports_profile(profile):
                        self._current_profile = profile
                        break

            swift_function = self.current_swift_function
            self._speculations = (
                build_speculations_per_line(swift_function)
                if swift_function is not None
                else {}
            )

            widget = self.GetWidget()
            if widget is not None:
                pyqt_widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(widget)
                pyqt_widget.setProperty(FUNC_EA_PROPERTY, self._start_ea)

            self.ClearLines()
            self._add_highlighted_content()
        except Exception as error:
            logger.error(f"Error updating Swift code viewer: {error}")

    def jump_to_swift_line(self, swift_line_number: int) -> None:
        display_line_number = swift_line_number + _SYNTHETIC_LINE_COUNT
        self.Jump(display_line_number - 1, 0, 0)

    def get_swift_line_number(self) -> int:
        display_line_number = (
            get_current_line_number_from_custom_viewer_twidget(self.GetWidget())
        )
        swift_line_number = _to_swift_line_number(display_line_number)
        if swift_line_number is None:
            return 1

        return swift_line_number

    def get_speculations_for_place(
        self, place: ida_kernwin.place_t
    ) -> ty.Sequence[NumberedSpeculation]:
        simple_place = ida_kernwin.place_t.as_simpleline_place_t(place)
        if simple_place is None:
            return ()

        display_line_number = simple_place.n + 1
        swift_line_number = _to_swift_line_number(display_line_number)
        if swift_line_number is None:
            return ()

        return self._speculations.get(swift_line_number, ())

    def OnKeydown(self, vkey: int, shift: int) -> int:
        """
        Handle key press events.

        Args:
            vkey: Virtual key code
            shift: Shift state

        Returns:
            1 if handled, 0 to pass to default handler
        """
        try:
            # Handle Escape key to close viewer
            if vkey == 27:  # ESCAPE
                self.Close()
                return 1

            return 0

        except Exception as e:
            logger.error(f"Error handling keydown: {e}")
            return 0


def _setup_tab_icon(created_widget: QWidget) -> None:
    """Setup tab icon"""

    try:
        icon = _load_swift_icon()
        if not icon.isNull():
            created_widget.setWindowIcon(icon)
        else:
            logger.warning("Failed to load window icon")
    except Exception as e:
        logger.error(f"Error setting window icon: {e}")


@cache
def _load_swift_icon() -> QtGui.QIcon:
    with importlib.resources.path(assets, "swift.png") as file_path:
        return QtGui.QIcon(str(file_path))


def create_swift_viewer(
    *,
    title: str = "Swift Code Viewer",
) -> ty.Optional[SwiftCodeViewer]:
    """
    Convenience function to create and show a Swift code viewer.

    Args:
        title: Window title for the viewer

    Returns:
        SwiftCodeViewer instance if successful, None otherwise
    """
    viewer = SwiftCodeViewer()
    if viewer.Create(title):
        return viewer
    else:
        logger.error("Failed to create Swift code viewer")
        return None


def _to_swift_line_number(
    display_line_number: int,
) -> ty.Optional[int]:
    swift_line_number = display_line_number - _SYNTHETIC_LINE_COUNT
    if swift_line_number < 1:
        return None
    return swift_line_number


def get_swift_viewer_from_action_context(
    ctx,
) -> ty.Optional[SwiftCodeViewer]:
    if ctx.widget is None:
        return None

    viewer = ida_kernwin.PluginForm.TWidgetToPyQtWidget(ctx.widget).property(
        SWIFT_VIEWER_PROPERTY
    )

    if isinstance(viewer, SwiftCodeViewer):
        return viewer

    return None
