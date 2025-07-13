import ida_kernwin

_PROGRESS_PLACEHOLDER = "<PROGRESS>"


class Cancelled(Exception):
    def __init__(self) -> None:
        super().__init__("Cancelled")


class WaitBox:
    """
    Simple wrapper for IDA's wait box. Must not be used from anyio task.
    """

    def __init__(self, text: str, *, items: int = 0):
        self._text = text
        self._items = items
        self._completed_items = 0

    def __enter__(self) -> "WaitBox":
        ida_kernwin.show_wait_box(self._format_message())
        return self

    def __exit__(self, *_) -> None:
        ida_kernwin.hide_wait_box()

    def start_new_task(self, text: str, *, items: int = 0) -> None:
        self._text = text
        self._items = items
        self._completed_items = 0
        self._update()

    def mark_items_complete(self, count: int) -> None:
        self._completed_items = min(self._completed_items + count, self._items)
        self._update()

    def _update(self) -> None:
        check_user_cancelled()
        ida_kernwin.replace_wait_box(self._format_message())

    def _format_message(self) -> str:
        message = self._text
        if self._items > 0:
            percentage = int(100 * self._completed_items / self._items)
            progress = f"{percentage}%"
            if _PROGRESS_PLACEHOLDER in message:
                message = message.replace(_PROGRESS_PLACEHOLDER, progress)
            else:
                message += f" ({progress})"
        return message


def check_user_cancelled():
    if ida_kernwin.user_cancelled():
        raise Cancelled()
