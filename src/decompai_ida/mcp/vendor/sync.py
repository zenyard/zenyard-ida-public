"""Shim replacing ida-pro-mcp's sync.py.

Upstream's `@idasync` marshalled tool bodies onto IDA's main thread via
`idaapi.execute_sync`. In decompai-ida we route through the repo's
`ida_tasks` instead, so the real implementation lives in
`decompai_ida.mcp.bridge`. The vendored api_* modules import everything
they need from `.sync`, so keeping these names here re-points all tools at
the bridge without editing any api module.
"""

import idaapi

from decompai_ida.mcp.bridge import (
    CancelledError as CancelledError,
    IDAError as IDAError,
    IDASyncError as IDASyncError,
    get_pre_call_batch as get_pre_call_batch,
    idasync as idasync,
    keep_batch as keep_batch,
    tool_timeout as tool_timeout,
)

# Matches upstream sync.py; utils.py imports `ida_major` for version gates.
ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))
