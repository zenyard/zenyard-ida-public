# ruff: noqa
import site
import sys
from pathlib import Path

DECOMPAI_PACKAGES = Path(__file__).parent / "decompai_packages"
if DECOMPAI_PACKAGES.is_dir():
    sys.path.insert(0, str(DECOMPAI_PACKAGES))
    site.addsitedir(str(DECOMPAI_PACKAGES))

from decompai_ida.plugin import PLUGIN_ENTRY, DecompaiPlugin
