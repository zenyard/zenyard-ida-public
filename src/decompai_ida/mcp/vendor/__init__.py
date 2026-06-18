"""Vendored subset of ida-pro-mcp (https://github.com/mrexodia/ida-pro-mcp, MIT).

Third-party licenses for everything in this directory are recorded in
`src/decompai_ida/mcp/vendor/README.md` and the accompanying `LICENSE.*` files
(`src/decompai_ida/mcp/vendor/LICENSE.ida-pro-mcp`,
`src/decompai_ida/mcp/vendor/LICENSE.ida-sigmaker`, and
`src/decompai_ida/mcp/vendor/zeromcp/LICENSE`).

Kept near-verbatim against upstream so the files stay diffable. The only
load-bearing change is `sync.py`, which is replaced by a shim re-exporting
the `ida_tasks`-based bridge in `decompai_ida.mcp.bridge`. Importing this
package registers every kept `@tool` on `rpc.MCP_SERVER` via import side
effects, mirroring upstream's `ida_mcp/__init__.py`.

Dropped from upstream: api_discovery, api_resources, trace, profile,
discovery, framework, http, the SIGPIPE guard (handled in plugin.py), and
the output-limit patch (output limiting is the MCP client/host's job).
"""

from decompai_ida.mcp.vendor import rpc as rpc
from decompai_ida.mcp.vendor import sync as sync
from decompai_ida.mcp.vendor import utils as utils

# Import all kept API modules to register @tool functions via side effects.
from decompai_ida.mcp.vendor import api_core as api_core
from decompai_ida.mcp.vendor import api_analysis as api_analysis
from decompai_ida.mcp.vendor import api_memory as api_memory
from decompai_ida.mcp.vendor import api_types as api_types
from decompai_ida.mcp.vendor import api_modify as api_modify
from decompai_ida.mcp.vendor import api_stack as api_stack
from decompai_ida.mcp.vendor import api_debug as api_debug
from decompai_ida.mcp.vendor import api_python as api_python
from decompai_ida.mcp.vendor import api_survey as api_survey
from decompai_ida.mcp.vendor import api_composite as api_composite
from decompai_ida.mcp.vendor import api_sigmaker as api_sigmaker

from decompai_ida.mcp.vendor.rpc import (
    MCP_SERVER as MCP_SERVER,
    MCP_UNSAFE as MCP_UNSAFE,
    MCP_EXTENSIONS as MCP_EXTENSIONS,
)
