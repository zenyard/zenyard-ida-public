"""
Event filter to automatically dismiss QMessageBox warnings.

This module provides a context manager that installs a Qt event filter to
automatically close warning message boxes. Supports both single-OK warnings
and two-button Help/OK warnings (the OK button is clicked, dismissing the
dialog without opening Help).

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
        Event filter that automatically dismisses QMessageBox warnings.

        Handles two warning shapes:
          - Single OK button: dialog is accepted.
          - Two buttons (Help + OK): the OK button is clicked so the warning
            is dismissed without invoking Help.
        """

        def eventFilter(self, obj: QObject, event: QEvent) -> bool:  # pyright: ignore[reportIncompatibleMethodOverride]
            if event.type() == QEvent.Show and isinstance(obj, QMessageBox):
                if obj.icon() == QMessageBox.Warning:
                    self._try_dismiss(obj)

            return super().eventFilter(obj, event)

        def _try_dismiss(self, box: "QMessageBox") -> None:
            buttons = box.buttons()
            if len(buttons) == 1:
                QTimer.singleShot(10, box.accept)
            elif len(buttons) == 2:
                # If one of the buttons is Help, click the other one. IDA
                # sometimes labels the dismiss button "OK" but exposes it as
                # a non-Ok standard button (e.g. Yes), so we identify it by
                # elimination rather than matching its specific role.
                help_buttons = [
                    b
                    for b in buttons
                    if box.standardButton(b) == QMessageBox.Help
                ]
                if len(help_buttons) == 1:
                    dismiss_button = next(
                        b for b in buttons if b is not help_buttons[0]
                    )
                    QTimer.singleShot(10, dismiss_button.click)

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
