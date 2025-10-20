from functools import cache
import typing as ty
import typing_extensions as tye
from itertools import chain
import ida_kernwin
import ida_lines
import importlib.resources
from qtpy import QtGui
from qtpy.QtWidgets import QWidget

from decompai_ida import assets
from decompai_ida import logger
from decompai_ida.ui.swift_highlighter import (
    SwiftHighlighter,
    SwiftTokenType,
    HighlightedToken,
)

FUNC_EA_PROPERTY = "start_ea"


class SwiftCodeViewer(ida_kernwin.simplecustviewer_t):
    """
    Swift code viewer widget using IDA's simplecustviewer_t with syntax highlighting.

    This widget displays Swift source code with syntax highlighting provided by
    Pygments. The entire Swift code is provided as a string in the constructor.
    """

    def __init__(self, start_ea: int, swift_code: str):
        """
        Initialize the Swift code viewer.`

        Args:
            swift_code: Swift source code to display
            title: Window title for the viewer
        """
        super().__init__()
        self._start_ea = start_ea
        self._swift_code = swift_code
        self._highlighter = SwiftHighlighter()

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

            created_widget.setProperty(FUNC_EA_PROPERTY, self._start_ea)

            # Add lines with syntax highlighting
            self._add_highlighted_content()

            logger.debug(f"Swift code viewer created: {title}")
            return True

        except Exception as e:
            logger.error(f"Error creating Swift code viewer: {e}")
            return False

    def _add_highlighted_content(self):
        """Add the Swift code content with syntax highlighting to the viewer."""
        try:
            if not self._swift_code:
                self.AddLine("No Swift code provided", ida_lines.SCOLOR_ERROR)
                return

            # Split code into lines
            lines = self._swift_code.splitlines(keepends=True)

            highlighted_tokens = self._highlighter.highlight(self._swift_code)
            next_highlighted_token = []

            # Add lines with highlighting
            line_start = 0

            for line in lines:
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
                highlighted_line = self._create_highlighted_line(
                    line, line_tokens, line_start
                )
                self.AddLine(highlighted_line)

                # Move to next line
                line_start = line_end

        except Exception as e:
            logger.error(f"Error adding highlighted content: {e}")
            # Fallback to plain text
            self.ClearLines()
            for line in self._swift_code.splitlines():
                self.AddLine(line)

    def _create_highlighted_line(
        self, line: str, line_tokens: ty.List[HighlightedToken], line_start: int
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


def _setup_tab_icon(created_widget: QWidget):
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
    start_ea: int, swift_code: str, title: str = "Swift Code Viewer"
) -> ty.Optional[SwiftCodeViewer]:
    """
    Convenience function to create and show a Swift code viewer.

    Args:
        swift_code: Swift source code to display
        title: Window title for the viewer

    Returns:
        SwiftCodeViewer instance if successful, None otherwise
    """
    viewer = SwiftCodeViewer(start_ea, swift_code)
    if viewer.Create(title):
        return viewer
    else:
        logger.error("Failed to create Swift code viewer")
        return None
