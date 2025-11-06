"""
Event filter to automatically dismiss QMessageBox warnings with only OK button.

This module provides a context manager that installs a Qt event filter to
automatically close warning message boxes that have a single OK button.
This is useful during long-running operations where IDA may show warnings
that would otherwise block execution.

IMPORTANT: The auto_dismiss_warnings() context manager must be called from
IDA's main/UI thread. It is suitable for use in ForegroundTask implementations
which already run on the main thread.
"""

from contextlib import contextmanager
import typing as ty

try:
    from qtpy.QtCore import QEvent, QObject, QTimer
    from qtpy.QtWidgets import QApplication, QMessageBox

    class _WarningAutoDismisser(QObject):
        """
        Event filter that automatically dismisses QMessageBox warnings with only OK button.

        This filter intercepts Show events for QMessageBox widgets and automatically
        accepts them if they are warning dialogs with a single OK button.
        """

        def eventFilter(self, obj: QObject, event: QEvent) -> bool:  # pyright: ignore[reportIncompatibleMethodOverride]
            """
            Filter Qt events to auto-dismiss matching warning dialogs.

            Args:
                obj: The object that generated the event
                event: The event to filter

            Returns:
                True if the event was handled, False otherwise
            """
            # Check if a widget is being shown
            if event.type() == QEvent.Show and isinstance(obj, QMessageBox):
                # Check if it's a warning message box
                if obj.icon() == QMessageBox.Warning:
                    buttons = obj.buttons()
                    if len(buttons) == 1:
                        QTimer.singleShot(10, obj.accept)

            # Pass through to parent event filter
            return super().eventFilter(obj, event)

    @contextmanager
    def auto_dismiss_warnings() -> ty.Iterator[None]:
        """
        Context manager that automatically dismisses warning QMessageBox dialogs.

        While this context is active, any QMessageBox with Warning icon and a single
        OK button will be automatically dismissed without user interaction.

        IMPORTANT: This must be called from IDA's main/UI thread. It is designed
        for use in ForegroundTask implementations which already run on the main thread.

        Example:
            with auto_dismiss_warnings():
                # Code that may trigger warning dialogs
                some_ida_operation()
        """
        dismisser = _WarningAutoDismisser()
        app = QApplication.instance()

        if app is not None:
            app.installEventFilter(dismisser)

        try:
            yield
        finally:
            if app is not None:
                app.removeEventFilter(dismisser)

except Exception:

    @contextmanager
    def auto_dismiss_warnings() -> ty.Iterator[None]:
        yield
