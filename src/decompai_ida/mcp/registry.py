"""Builds the MCP server with decompai-ida's deduplicated tool set.

Importing the vendored package registers every kept tool on the shared
`MCP_SERVER`. `build_server` then filters that registry down to the chosen
non-overlapping subset (`_KEEP_TOOLS`) and neutralizes upstream's extension
gating so the debugger tools are reachable without the `?ext=dbg` opt-in.
"""

from decompai_ida.mcp.vendor import (
    MCP_EXTENSIONS,
    MCP_SERVER,
)
from decompai_ida.mcp.vendor.zeromcp import McpServer

# The deduplicated keep-list: best fit from each overlapping group of the
# upstream ida-pro-mcp tools. See the implementation plan for the rationale
# behind each drop.
_KEEP_TOOLS: frozenset[str] = frozenset(
    {
        # core
        "server_health",
        "lookup_funcs",
        "entity_query",
        "imports_query",
        "idb_save",
        "search_text",
        # analysis
        "decompile",
        "disasm",
        "xref_query",
        "xrefs_to_field",
        "callees",
        "find_bytes",
        "find",
        "insn_query",
        "basic_blocks",
        "callgraph",
        "export_funcs",
        # composite
        "analyze_function",
        "analyze_component",
        "trace_data_flow",
        # memory
        "get_bytes",
        "get_int",
        "get_string",
        "patch",
        "put_int",
        # modify
        "set_comments",
        "patch_asm",
        "rename",
        "define_func",
        "define_code",
        "undefine",
        # types
        "declare_type",
        "enum_upsert",
        "read_struct",
        "type_query",
        "type_inspect",
        "set_type",
        "infer_types",
        # stack
        "stack_frame",
        "declare_stack",
        "delete_stack",
        # survey
        "survey_binary",
        # sigmaker
        "make_signature",
        "make_signature_for_range",
        "find_xref_signatures",
        # debug
        "dbg_start",
        "dbg_status",
        "dbg_exit",
        "dbg_continue",
        "dbg_run_to",
        "dbg_step_into",
        "dbg_step_over",
        "dbg_bps",
        "dbg_add_bp",
        "dbg_delete_bp",
        "dbg_toggle_bp",
        "dbg_set_bp_condition",
        "dbg_regs_all",
        "dbg_regs",
        "dbg_stacktrace",
        "dbg_read",
        "dbg_write",
        # python
        "py_eval",
    }
)


def build_server() -> McpServer:
    """Return the shared MCP server filtered to the deduplicated tool set.

    Mutates the process-wide `MCP_SERVER` singleton in place; safe to call
    more than once (filtering only ever removes tools).
    """
    registered = set(MCP_SERVER.tools.methods)

    missing = _KEEP_TOOLS - registered
    if missing:
        # A name in _KEEP_TOOLS that no vendored module registered — almost
        # certainly a typo or a dropped import. Surface it loudly.
        raise RuntimeError(
            f"MCP tools missing from registry: {sorted(missing)}"
        )

    for name in registered - _KEEP_TOOLS:
        del MCP_SERVER.tools.methods[name]

    # Neutralize extension gating: with the registry cleared, the per-request
    # ?ext=<group> check in zeromcp becomes a no-op and every kept tool
    # (including the dbg_* group) is listed and callable.
    MCP_EXTENSIONS.clear()

    # Enforce the Streamable HTTP session lifecycle: clients must `initialize`
    # and reuse the returned Mcp-Session-Id on subsequent requests.
    MCP_SERVER.require_streamable_http_session = True

    return MCP_SERVER
