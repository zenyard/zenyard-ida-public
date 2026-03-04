# Must be done before any import Qt
# No-op condition to stop formatters from reorganizing imports
if True:
    from decompai_ida.ui.setup_qt import setup_qt_sync

    setup_qt_sync()

from threading import Thread

import anyio
import ida_idaapi

from decompai_ida import configuration, ida_tasks
from decompai_ida.main import main, stop


class DecompaiPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_MULTI  # type: ignore
    wanted_name = "Zenyard"

    def init(self):
        # IDA disables Python default handling of SIGPIPE, making the process
        # crash on socket errors.
        try:
            import signal

            signal.signal(signal.SIGPIPE, signal.SIG_IGN)
        except Exception:
            # Signals not supported (e.g. Windows).
            pass

        return DecompaiPlugmod()


class DecompaiPlugmod(ida_idaapi.plugmod_t):
    def __init__(self):
        self._thread = Thread(target=main_loop)
        self._thread.start()

    def run(self, _arg):  # type: ignore
        accepted = configuration.show_configuration_dialog_sync()
        if accepted:
            stop(restart=True)

    def __del__(self):
        # We must wait to allow thread to fully shut down, as IDA is about to
        # close and cleanup may require IDA API.
        stop(wait=True)

        # Hooks must be immediately removed to avoid crash.
        ida_tasks.unhook_all_sync()


def main_loop():
    anyio.run(main)


def PLUGIN_ENTRY():
    import ida_kernwin  # type: ignore

    try:
        is_lib = ida_kernwin.is_ida_library()  # type: ignore
    except Exception:
        try:
            is_lib = ida_kernwin.is_ida_library(None, 0, None)  # type: ignore
        except Exception:
            is_lib = False

    if is_lib:
        return

    return DecompaiPlugin()
