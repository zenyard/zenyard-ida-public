import importlib.resources
import typing as ty
import typing_extensions as tye
from dataclasses import dataclass
from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtCore import pyqtSignal
from decompai_ida import logger
import ida_kernwin
import ida_name
import idautils
import idaapi
from textwrap import dedent

from decompai_ida import assets
from decompai_ida.ida_tasks import AsyncCallback
from decompai_ida.model import Message

if ty.TYPE_CHECKING:
    from decompai_ida.model import CopilotModel

# Constants
MAX_INPUT_LINE_HEIGHT = 8
TEXT_MARGIN_ADJUSTMENT = 12
BUTTON_SIZE = QtCore.QSize(25, 25)
LAYOUT_MARGIN = 5
LAYOUT_SPACING = 0
MESSAGE_MARGIN_LEFT = 15
MESSAGE_MARGIN_TOP = 5
SCROLL_TO_BOTTOM_THRESHOLD = 50


class CopilotStyles:
    """Centralized styling for the Copilot UI components."""

    USER_INPUT_FRAME = """
        QFrame {
            background-color: white;
            border-width: 1;
            border-radius: 3;
            border-style: solid;
            border-color: #b8b8b8;
        }
    """

    USER_INPUT_FRAME_DISABLED = """
        QFrame {
            background-color: #e1e1e1;
            border-width: 1;
            border-radius: 3;
            border-style: solid;
            border-color: #b8b8b8;
        }
    """

    USER_TEXT_INPUT = "QTextEdit { border: none; }"

    MESSAGE_HTML_TEMPLATE = dedent("""
    <span style="color: #5C45A0"><b>{sender}</b></span>
                                   
    {text}
    
    """)

    SEND_BUTTON_SEND = "➤"
    SEND_BUTTON_STOP = "■"


@dataclass
class ChatState:
    messages: ty.List[Message]
    in_progress: bool


class CopilotViewModel(QtCore.QObject):
    """
    ViewModel that bridges CopilotModel and UI components.
    Exposes Qt signals for UI and provides methods to modify the model.
    """

    # Qt signals for UI updates
    messages_changed = pyqtSignal(list)  # list[Message]
    copilot_active_changed = pyqtSignal(bool)

    def __init__(self, copilot_model: "CopilotModel", parent=None):
        super().__init__(parent)
        self._copilot_model = copilot_model

    def get_messages(self) -> ty.List[Message]:
        """Get current messages."""
        return self._copilot_model.messages.copy()

    def is_copilot_active(self) -> bool:
        """Check if copilot is currently processing."""
        return self._copilot_model.is_active

    def add_message(self, message: Message) -> None:
        """Add a message and notify model."""
        self._copilot_model.messages.append(message)
        self._copilot_model.notify_update()

    def request_stop(self) -> None:
        """Request to stop current operation."""
        self._copilot_model.stop_requested = True
        self._copilot_model.notify_update()

    def clear_conversation(self) -> None:
        """Clear all messages."""
        self._copilot_model.messages.clear()
        self._copilot_model.clear_requested = True
        self._copilot_model.notify_update()

    def update_from_model(self) -> None:
        """Update UI signals based on current model state."""
        self.messages_changed.emit(self._copilot_model.messages)
        self.copilot_active_changed.emit(self.is_copilot_active())


class ChatDisplay(QtWidgets.QTextEdit):
    """Chat display widget that shows conversation messages with symbol navigation."""

    _last_messages_html = ty.Optional[str]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setObjectName("ChatDisplay")
        self.setAccessibleName("Chat conversation display")
        self.setAccessibleDescription(
            "Double-click on symbols to navigate to them in IDA"
        )
        self._last_messages_html = None

    def mouseDoubleClickEvent(self, e):
        """Handle double-click events to navigate to symbols in IDA."""
        try:
            cursor = self.cursorForPosition(e.pos())
            selected_symbol = ida_name.extract_name(
                cursor.block().text(), cursor.positionInBlock()
            )
            if selected_symbol:
                self._jump_to_symbol(selected_symbol)
        except Exception as ex:
            logger.error(f"Error handling symbol double-click: {ex}")
        finally:
            super().mouseDoubleClickEvent(e)

    def _jump_to_symbol(self, symbol: str):
        """Navigate to a symbol in IDA if it exists."""
        try:
            if symbol.startswith("0x"):
                ida_kernwin.jumpto(int(symbol, 16))
            else:
                ea = ida_name.get_name_ea(idaapi.BADADDR, symbol)
                if ea != idaapi.BADADDR:
                    ida_kernwin.jumpto(ea)
                    logger.debug(f"Navigated to symbol: {symbol} at {hex(ea)}")
                else:
                    ea = _find_demangled_symbol_ea(symbol)
                    if ea is not None:
                        ida_kernwin.jumpto(ea)
                    else:
                        logger.debug(f"Symbol not found: {symbol}")
        except Exception as e:
            logger.debug(f"Failed to navigate to symbol {symbol}: {e}")

    def set_messages(self, messages: ty.List[Message]):
        """Update the chat display with new messages."""
        try:
            html_content = "".join(
                [
                    CopilotStyles.MESSAGE_HTML_TEMPLATE.format(
                        sender=_get_message_sender(message),
                        margin_left=MESSAGE_MARGIN_LEFT,
                        margin_top=MESSAGE_MARGIN_TOP,
                        text=message.text,
                    )
                    for message in messages
                ]
            )
            if self._last_messages_html == html_content:
                return
            self._last_messages_html = html_content

            scroll = self.verticalScrollBar()
            scroll_value = scroll.value()
            should_scroll_to_bottom = False
            # TODO: Qt sometimes loses a scroll to the bottom
            if scroll.maximum() - scroll.value() < SCROLL_TO_BOTTOM_THRESHOLD:
                should_scroll_to_bottom = True
            self.setMarkdown(html_content)
            if should_scroll_to_bottom:
                self.moveCursor(QtGui.QTextCursor.End)
            else:
                scroll.setValue(scroll_value)
        except Exception as e:
            logger.error(f"Failed to update chat messages: {e}")
            self.setPlainText("Error displaying messages")


def _find_demangled_symbol_ea(symbol: str) -> ty.Optional[int]:
    for func_ea in idautils.Functions():
        if symbol == ida_name.get_demangled_name(
            func_ea,
            ida_name.MNG_NODEFINIT,  # type: ignore
            0,
        ):
            return func_ea


def _get_message_sender(message: Message) -> str:
    """Get the display name for a message sender."""
    match message.sender:
        case "AI":
            return "Copilot"
        case "User":
            return "You"
        case _:
            _: tye.Never = message.sender
            return "Unknown"


class UserTextInput(QtWidgets.QTextEdit):
    """Multi-line text input widget with auto-sizing and message sending."""

    message_sent = pyqtSignal(Message)

    def __init__(
        self,
        parent=None,
        max_lines=MAX_INPUT_LINE_HEIGHT,
    ):
        super().__init__(parent)
        self._max_lines = max_lines + 1
        self._font_metrics = None

        self.setObjectName("UserTextInput")
        self.setAccessibleName("Message input")
        self.setAccessibleDescription(
            "Type your message here. Press Enter to send, Shift+Enter for new line"
        )

        self.setStyleSheet(CopilotStyles.USER_TEXT_INPUT)
        self.setPlaceholderText("Type a message...")
        self.setToolTip(
            "Type your message here. Press Enter to send, Shift+Enter for new line"
        )

        try:
            self.textChanged.connect(self._adjust_height)
            self._adjust_height()
        except Exception as e:
            logger.error(f"Failed to setup UserTextInput: {e}")

    def _line_height(self) -> int:
        """Get the line height for the current font."""
        if self._font_metrics is None:
            self._font_metrics = QtGui.QFontMetrics(self.font())
        return self._font_metrics.lineSpacing()

    def _count_wrapped_lines(self) -> int:
        """Count the number of wrapped lines in the document."""
        try:
            doc = self.document()
            height = doc.size().height()
            line_height = self._line_height()
            return max(1, int(height / line_height)) if line_height > 0 else 1
        except Exception as e:
            logger.error(f"Error counting wrapped lines: {e}")
            return 1

    def _adjust_height(self):
        """Adjust the widget height based on content."""
        try:
            line_count = self._count_wrapped_lines()
            line_height = self._line_height()
            max_height = line_height * self._max_lines

            if line_count >= self._max_lines:
                new_height = max_height
                self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
            else:
                new_height = line_height * line_count + TEXT_MARGIN_ADJUSTMENT
                self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)

            self.setFixedHeight(new_height)
        except Exception as e:
            logger.error(f"Error adjusting text input height: {e}")

    def keyPressEvent(self, e):
        """Handle key press events for message sending."""
        try:
            if e.key() in (QtCore.Qt.Key_Return, QtCore.Qt.Key_Enter):
                if e.modifiers() == QtCore.Qt.ShiftModifier:
                    super().keyPressEvent(e)
                else:
                    self.send_message()
            else:
                super().keyPressEvent(e)
        except Exception as ex:
            logger.error(f"Error handling key press: {ex}")
            super().keyPressEvent(e)

    def send_message(self):
        """Send the current message if not empty."""
        try:
            message_text = self.toPlainText().strip()
            if message_text:
                self.message_sent.emit(Message("User", message_text))
                self.clear()
                self.setDisabled(True)
        except Exception as e:
            logger.error(f"Error sending message: {e}")


class UserInputPanel(QtWidgets.QWidget):
    """Panel containing send/stop and clear conversation buttons."""

    send_requested = pyqtSignal()
    stop_requested = pyqtSignal()
    clear_requested = pyqtSignal()

    def __init__(self, parent=None, in_progress=False):
        super().__init__(parent)
        self._in_progress = in_progress

        self.setObjectName("UserInputPanel")

        self._setup_buttons()
        self._setup_layout()
        self._connect_signals()

    def _setup_buttons(self):
        """Initialize the buttons with proper styling and accessibility."""
        self.send_stop_button = QtWidgets.QPushButton()
        self.send_stop_button.setFixedSize(BUTTON_SIZE)
        self.send_stop_button.setObjectName("SendStopButton")

        self.clear_conversation_button = QtWidgets.QPushButton(
            "Clear Conversation"
        )
        self.clear_conversation_button.setObjectName("ClearConversationButton")
        self.clear_conversation_button.setToolTip(
            "Clear the current conversation"
        )

        self._update_icon()

    def _setup_layout(self):
        """Setup the layout for the panel."""
        layout = QtWidgets.QHBoxLayout()
        layout.setContentsMargins(
            LAYOUT_MARGIN, LAYOUT_MARGIN, LAYOUT_MARGIN, LAYOUT_MARGIN
        )
        layout.addWidget(
            self.clear_conversation_button, alignment=QtCore.Qt.AlignLeft
        )
        layout.addWidget(self.send_stop_button, alignment=QtCore.Qt.AlignRight)
        self.setLayout(layout)

    def _connect_signals(self):
        """Connect button signals to appropriate slots."""
        try:
            self.clear_conversation_button.clicked.connect(self.clear_requested)
            self.send_stop_button.clicked.connect(self._handle_send_stop_click)
        except Exception as e:
            logger.error(f"Failed to connect UserInputPanel signals: {e}")

    def _handle_send_stop_click(self):
        """Handle send/stop button click based on current state."""
        try:
            if self._in_progress:
                self.stop_requested.emit()
            else:
                self.send_requested.emit()
        except Exception as e:
            logger.error(f"Error handling send/stop click: {e}")

    def set_in_progress(self, in_progress: bool):
        """Update the panel state based on processing status."""
        try:
            self._in_progress = in_progress
            self._update_icon()
            self.clear_conversation_button.setDisabled(in_progress)
        except Exception as e:
            logger.error(f"Error setting in_progress state: {e}")

    def _update_icon(self):
        """Update the send/stop button icon and tooltip based on state."""
        try:
            if self._in_progress:
                self.send_stop_button.setText(CopilotStyles.SEND_BUTTON_STOP)
                self.send_stop_button.setToolTip("Stop current operation")
                self.send_stop_button.setAccessibleName("Stop button")
            else:
                self.send_stop_button.setText(CopilotStyles.SEND_BUTTON_SEND)
                self.send_stop_button.setToolTip("Send message")
                self.send_stop_button.setAccessibleName("Send button")
        except Exception as e:
            logger.error(f"Error updating button icon: {e}")


class UserInput(QtWidgets.QFrame):
    """Combined user input widget with text field and control buttons."""

    message_sent = pyqtSignal(Message)
    stop_requested = pyqtSignal()
    clear_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("UserInput")
        self.setAutoFillBackground(True)
        self.setStyleSheet(CopilotStyles.USER_INPUT_FRAME)
        self._in_progress = False

        self._setup_components()
        self._setup_layout()
        self._connect_signals()

    def _setup_components(self):
        """Initialize child components."""
        self.user_text_input = UserTextInput()
        self.user_input_panel = UserInputPanel()

    def _setup_layout(self):
        """Setup the layout for the input widget."""
        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(
            LAYOUT_SPACING, LAYOUT_SPACING, LAYOUT_SPACING, LAYOUT_SPACING
        )
        layout.setSpacing(LAYOUT_SPACING)

        layout.addWidget(self.user_text_input, alignment=QtCore.Qt.AlignTop)
        layout.addWidget(self.user_input_panel, alignment=QtCore.Qt.AlignBottom)

        self.setLayout(layout)
        self.setContentsMargins(
            LAYOUT_SPACING, LAYOUT_SPACING, LAYOUT_SPACING, LAYOUT_SPACING
        )

    def _connect_signals(self):
        """Connect signals between components."""
        try:
            self.user_text_input.message_sent.connect(self.message_sent)
            self.user_input_panel.send_requested.connect(
                self.user_text_input.send_message
            )
            self.user_input_panel.stop_requested.connect(self.stop_requested)
            self.user_input_panel.clear_requested.connect(self.clear_requested)
        except Exception as e:
            logger.error(f"Failed to connect UserInput signals: {e}")

    def input_focus(self):
        """Set focus to the text input field."""
        try:
            self.user_text_input.setFocus()
        except Exception as e:
            logger.error(f"Error setting input focus: {e}")

    def set_in_progress(self, in_progress: bool):
        """Update the input state based on processing status."""
        try:
            self.user_text_input.setDisabled(in_progress)
            self.user_input_panel.set_in_progress(in_progress)

            if in_progress:
                self.setStyleSheet(CopilotStyles.USER_INPUT_FRAME_DISABLED)
                self._in_progress = True
            else:
                self.setStyleSheet(CopilotStyles.USER_INPUT_FRAME)
                # Focus input only if previously had focus and currently no other widget gained focus
                if (
                    self._in_progress
                    and QtWidgets.QApplication.focusWidget() is None
                ):
                    self.input_focus()
                self._in_progress = False
        except Exception as e:
            logger.error(f"Error setting in_progress state: {e}")


class CopilotChat(QtWidgets.QWidget):
    """Main chat widget combining display and input components."""

    message_sent = pyqtSignal(Message)
    stop_requested = pyqtSignal()
    clear_requested = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setObjectName("CopilotChat")

        self._setup_components()
        self._setup_layout()
        self._connect_signals()

    def _setup_components(self):
        """Initialize chat components."""
        self.chat_display = ChatDisplay()
        self.input_field = UserInput()

    def _setup_layout(self):
        """Setup the main chat layout."""
        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(
            LAYOUT_SPACING, LAYOUT_SPACING, LAYOUT_SPACING, LAYOUT_SPACING
        )
        layout.setSpacing(LAYOUT_SPACING)

        layout.addWidget(self.chat_display)
        layout.addWidget(self.input_field)

        self.setLayout(layout)

    def _connect_signals(self):
        """Connect signals between chat components."""
        try:
            self.input_field.message_sent.connect(self.message_sent)
            self.input_field.stop_requested.connect(self.stop_requested)
            self.input_field.clear_requested.connect(self.clear_requested)
        except Exception as e:
            logger.error(f"Failed to connect CopilotChat signals: {e}")

    def set_state(self, state: ChatState):
        """Update the chat state with new messages and progress status."""
        try:
            self.chat_display.set_messages(state.messages)
            self.input_field.set_in_progress(state.in_progress)
        except Exception as e:
            logger.error(f"Error setting chat state: {e}")

    def input_focus(self):
        """Set focus to the input field."""
        try:
            self.input_field.input_focus()
        except Exception as e:
            logger.error(f"Error setting chat input focus: {e}")


class CopilotWindow(ida_kernwin.PluginForm):
    """IDA Pro plugin form for the Copilot chat interface."""

    _view_model: CopilotViewModel
    copilot_chat: ty.Optional[CopilotChat]

    def __init__(self, view_model: CopilotViewModel):
        super().__init__()
        self._view_model = view_model
        self.copilot_chat = None

    def OnCreate(self, form):  # type: ignore[override]
        """Initialize the chat window when created by IDA."""
        try:
            self.parent = self.FormToPyQtWidget(form)  # type: ignore[attr-defined]
            self._setup_window_properties()
            self._setup_layout()
            self._connect_view_model()
        except Exception as e:
            logger.error(f"Failed to create ChatWindow: {e}")

    def _setup_window_properties(self):
        """Setup window icon and properties."""
        try:
            with importlib.resources.path(
                assets, "zenyard_icon.png"
            ) as file_path:
                icon = QtGui.QIcon(str(file_path))
                if not icon.isNull():
                    self.parent.setWindowIcon(icon)
                else:
                    logger.warning("Failed to load window icon")
        except Exception as e:
            logger.error(f"Error setting window icon: {e}")

        self.parent.setObjectName("ChatWindow")

    def _setup_layout(self):
        """Setup the main window layout."""
        try:
            layout = QtWidgets.QVBoxLayout()
            self.copilot_chat = CopilotChat()

            layout.addWidget(self.copilot_chat)
            layout.setContentsMargins(
                LAYOUT_SPACING, LAYOUT_SPACING, LAYOUT_SPACING, LAYOUT_SPACING
            )
            layout.setSpacing(LAYOUT_SPACING)

            self.parent.setLayout(layout)
        except Exception as e:
            logger.error(f"Error setting up chat window layout: {e}")

    def input_focus(self):
        """Set focus to the chat input field."""
        if self.copilot_chat is None:
            return
        try:
            self.copilot_chat.input_focus()
        except Exception as e:
            logger.error(f"Error setting chat window input focus: {e}")

    def _connect_view_model(self):
        """Connect the view model to the UI components."""
        if self.copilot_chat is None:
            return
        try:
            # Connect UI signals to view model methods
            self.copilot_chat.message_sent.connect(
                AsyncCallback(self._view_model.add_message)
            )

            self.copilot_chat.stop_requested.connect(
                AsyncCallback(self._view_model.request_stop)
            )
            self.copilot_chat.clear_requested.connect(
                AsyncCallback(self._view_model.clear_conversation)
            )

            # Connect view model signals to UI updates
            self._view_model.messages_changed.connect(self._update_messages)
            self._view_model.copilot_active_changed.connect(
                self._update_active_state
            )

            # Initialize with current state
            self._update_messages(self._view_model.get_messages())
            self._update_active_state(self._view_model.is_copilot_active())

        except Exception as e:
            logger.error(f"Error connecting view model: {e}")

    def _update_messages(self, messages: ty.List[Message]):
        """Update the chat display with new messages."""
        if self.copilot_chat is None:
            return
        try:
            chat_state = ChatState(messages=messages, in_progress=False)
            self.copilot_chat.set_state(chat_state)
        except Exception as e:
            logger.error(f"Error updating messages: {e}")

    def _update_active_state(self, is_active: bool):
        """Update the UI based on copilot active state."""
        if self.copilot_chat is None:
            return
        try:
            # Update the in_progress state which controls UI disable/enable
            current_messages = (
                self._view_model.get_messages() if self._view_model else []
            )
            chat_state = ChatState(
                messages=current_messages, in_progress=is_active
            )
            self.copilot_chat.set_state(chat_state)
        except Exception as e:
            logger.error(f"Error updating active state: {e}")
