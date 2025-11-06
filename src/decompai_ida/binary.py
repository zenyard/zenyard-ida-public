import gzip
import io
import shutil
import typing as ty
from dataclasses import dataclass
from pathlib import Path

import anyio
import ida_bytes
import ida_loader
import ida_nalt
import ida_segment
import idc
import idautils
from anyio import to_thread

from decompai_ida import ida_tasks


MACHO_PLATFORM = {
    1: "macos",
    2: "ios",
}


def get_size_sync() -> int:
    """
    Gets approximate size of the input binary, by summing sizes of segments
    that are mapped to input file.
    """

    def get_mapped_size(segment_start: int) -> int:
        file_offset = ida_loader.get_fileregion_offset(segment_start)
        if file_offset < 0:
            # Not mapped to file (e.g. stack)
            return 0

        segment = ida_segment.getseg(segment_start)
        return segment.size()

    return sum(
        get_mapped_size(segment_start) for segment_start in idautils.Segments()
    )


def get_binary_path_sync() -> Path:
    if not is_idb_open_sync():
        raise Exception("No database")
    return Path(ida_nalt.get_input_file_path())


def get_idb_path_sync() -> Path:
    if not is_idb_open_sync():
        raise Exception("No database")
    return Path(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))


def is_idb_open_sync() -> bool:
    return len(ida_loader.get_path(ida_loader.PATH_TYPE_IDB)) > 0


@dataclass(frozen=True)
class InputFile:
    name: str
    data: bytes
    type: str


def _get_file_type_sync() -> str:
    """
    Returns the IDA file type name.
    """
    return ida_loader.get_file_type_name()


async def read_compressed_input_file() -> InputFile:
    # Check if it's an Apple dyld cache
    file_type = await ida_tasks.run(_get_file_type_sync)
    if file_type.lower().startswith("apple dyld cache"):
        # For dyld cache, return empty data
        return InputFile(name="dyld", data=b"", type="dyld")

    # Prefer original binary
    input_path = anyio.Path(await ida_tasks.run(get_binary_path_sync))
    name = "binary.gz"
    file_type_str = "binary"

    if not await input_path.exists():
        # Fallback to IDB
        input_path = anyio.Path(await ida_tasks.run(get_idb_path_sync))
        name = "idb.gz"
        file_type_str = "idb"

    if not await input_path.exists():
        # Give up
        raise Exception("No input file")

    async with await input_path.open("rb") as input_file:
        data = await to_thread.run_sync(
            _compress_gzip, input_file.wrapped, abandon_on_cancel=True
        )

    return InputFile(name=name, data=data, type=file_type_str)


def _compress_gzip(file_obj: ty.IO[bytes]) -> bytes:
    compressed_buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed_buffer, mode="wb") as gz:
        shutil.copyfileobj(file_obj, gz)
    return compressed_buffer.getvalue()


def get_platform_and_os_version_sync() -> (
    ty.Tuple[ty.Optional[str], ty.Optional[str]]
):
    """
    Extracts platform and OS version from Mach-O build_version_command structure.
    Returns tuple of (platform, os_version), both can be None if extraction fails.
    """
    platform = None
    os_version = None

    build_version_command = idc.get_struc_id("build_version_command")
    if build_version_command == idc.BADADDR:
        return (platform, os_version)

    first_xref = next(idautils.XrefsTo(build_version_command), None)
    if first_xref is None:
        return (platform, os_version)

    ea = first_xref.frm  # type: ignore
    for offset, name, size_in_bytes in idautils.StructMembers(
        build_version_command
    ):
        if name not in ("platform", "sdk"):
            continue

        field_bytes = ida_bytes.get_bytes(ea + offset, size_in_bytes)
        if field_bytes is None:
            continue

        field_value = int.from_bytes(field_bytes, byteorder="little")

        if name == "platform":
            platform = MACHO_PLATFORM.get(field_value)
        elif name == "sdk":
            major_ver = (field_value & 0xFF0000) >> 16
            minor_ver = (field_value & 0xFF00) >> 8
            patch_ver = field_value & 0xFF
            os_version = f"{major_ver}.{minor_ver}.{patch_ver}"

    return (platform, os_version)
