import re
import ida_kernwin
import os


def setup_qt_sync():
    "Configures QT_API according to IDA version"

    ida_version = _get_ida_version()
    if ida_version >= (9, 2):
        os.environ["QT_API"] = "pyside6"
    else:
        os.environ["QT_API"] = "pyqt5"


_IDA_VERSION_PATTERN = re.compile(r"^(\d+)\.(\d+)")


def _get_ida_version() -> tuple[int, int]:
    ida_version = ida_kernwin.get_kernel_version()
    m = _IDA_VERSION_PATTERN.match(ida_version)
    if m is None:
        raise Exception("Can't parse IDA version")
    return (int(m.group(1)), int(m.group(2)))
