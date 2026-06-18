# Vendored third-party components

The files in this directory are derived from third-party, MIT-licensed
projects. They retain their original licenses and are **not** covered by the
AGPL-3.0 license that governs the rest of this repository (see the root
[`LICENSE`](../../../../LICENSE)). MIT is one-way compatible with AGPL-3.0, so
these components may be distributed as part of the larger AGPL work while each
keeps its own MIT grant.

| Component | Source | License | Files |
| --- | --- | --- | --- |
| ida-pro-mcp | https://github.com/mrexodia/ida-pro-mcp | MIT — © 2025 Duncan Ogilvie ([`LICENSE.ida-pro-mcp`](LICENSE.ida-pro-mcp)) | `rpc.py`, `sync.py`, `utils.py`, `compat.py`, `api_*.py` |
| zeromcp | https://github.com/mrexodia/zeromcp | MIT — © 2025 Duncan Ogilvie ([`zeromcp/LICENSE`](zeromcp/LICENSE)) | `zeromcp/` |
| ida-sigmaker | https://github.com/mahmoudimus/ida-sigmaker | MIT — © 2024 Mahmoud Abdelkader ([`LICENSE.ida-sigmaker`](LICENSE.ida-sigmaker)) | `_sigmaker.py` |

Local modifications (e.g. the `sync.py` shim, trimmed modules, and `_meta`
tagging) are documented in [`__init__.py`](__init__.py).
