"""Trimmed port of ida-pro-mcp's rpc.py.

Provides the tool registry singleton and the decorators the api_* modules
import (`tool`, `unsafe`, `ext`, `resource`). Upstream's output-size limiting
patch (`_install_tools_call_patch`, output cache, download URLs) is removed:
output limiting is the MCP client/host's responsibility.
"""

import typing as ty

from .zeromcp import (
    McpRpcRegistry,
    McpServer,
    McpToolError,
    McpHttpRequestHandler,
)

MCP_UNSAFE: set[str] = set()
MCP_EXTENSIONS: dict[str, set[str]] = {}  # group -> set of function names
MCP_SERVER = McpServer("decompai-ida-mcp", extensions=MCP_EXTENSIONS)


class ToolAnnotations(ty.TypedDict, total=False):
    """MCP ToolAnnotations — behavioral hints (all optional, all advisory)."""

    title: str
    readOnlyHint: bool
    destructiveHint: bool
    idempotentHint: bool
    openWorldHint: bool


# Attribute names carrying metadata from the decorator to schema generation
# (see McpServer._generate_tool_schema). Same pattern as tool_timeout /
# keep_batch in bridge.py.
ANNOTATIONS_ATTR = "__ida_mcp_annotations__"
META_ATTR = "__ida_mcp_meta__"

# _meta key under which a tool advertises its action category. Only the tool
# groups below carry it; tools outside these groups have no action category.
ACTION_CATEGORY_META_KEY = "zenyard.ai/action-category"

type ActionCategory = ty.Literal["debugger", "signature", "scripts"]

ACTION_CATEGORY_DEBUGGER: ActionCategory = "debugger"
ACTION_CATEGORY_SIGNATURE: ActionCategory = "signature"
ACTION_CATEGORY_SCRIPTS: ActionCategory = "scripts"


def tool(
    func: ty.Optional[ty.Callable] = None,
    *,
    annotations: ty.Optional[ToolAnnotations] = None,
    _meta: ty.Optional[dict[str, ty.Any]] = None,
):
    """Register an MCP tool.

    Usage:
        @tool
        def foo(...): ...

        @tool(annotations={"readOnlyHint": True}, _meta={"x/group": "core"})
        def bar(...): ...
    """

    def decorator(f: ty.Callable) -> ty.Callable:
        if annotations is not None:
            setattr(f, ANNOTATIONS_ATTR, annotations)
        if _meta is not None:
            setattr(f, META_ATTR, _meta)
        return MCP_SERVER.tool(f)

    # Bare `@tool` -> func is the decorated function.
    # Called `@tool(...)` -> func is None, return the decorator.
    return decorator(func) if func is not None else decorator


def resource(uri):
    return MCP_SERVER.resource(uri)


def unsafe(func):
    MCP_UNSAFE.add(func.__name__)
    return func


def ext(group: str):
    """Mark a tool as belonging to an extension group.

    Tools in extension groups are hidden by default. Enable via ?ext=group query param.
    Example: @ext("dbg") marks debugger tools that require ?ext=dbg to be visible.
    """

    def decorator(func):
        if group not in MCP_EXTENSIONS:
            MCP_EXTENSIONS[group] = set()
        MCP_EXTENSIONS[group].add(func.__name__)
        return func

    return decorator


__all__ = [
    "McpRpcRegistry",
    "McpServer",
    "McpToolError",
    "McpHttpRequestHandler",
    "MCP_SERVER",
    "MCP_UNSAFE",
    "MCP_EXTENSIONS",
    "ToolAnnotations",
    "ACTION_CATEGORY_META_KEY",
    "ActionCategory",
    "ACTION_CATEGORY_DEBUGGER",
    "ACTION_CATEGORY_SIGNATURE",
    "ACTION_CATEGORY_SCRIPTS",
    "tool",
    "unsafe",
    "ext",
    "resource",
]
