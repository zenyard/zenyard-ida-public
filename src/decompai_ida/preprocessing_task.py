import re
import typing as ty
from collections import defaultdict
from dataclasses import dataclass
from inspect import cleandoc

import ida_auto
import ida_bytes
import ida_dirtree
import ida_funcs
import ida_hexrays
import ida_ida
import ida_lines
import ida_loader
import ida_name
import ida_netnode
import ida_search
import ida_segment
import ida_typeinf
import idaapi
import idc
import idautils

from decompai_ida import ida_tasks, logger
from decompai_ida.tasks import ForegroundTask
from decompai_ida.warning_auto_dismisser import auto_dismiss_warnings

_PREPROCESSING_WAITBOX_TEXT = cleandoc("""
    Zenyard is Running Preprocessing

    Loading external segments and resolving references (<PROGRESS>)
""")

# Regex to extract error operands from IDA disassembly lines
_ERROR_OPERAND_RE = re.compile(r"\x01\x12(.*?)\x02\x12")

# Minimum address threshold for valid segment addresses
_MIN_SEGMENT_ADDRESS = 0x180000000

_READONLY_SEGMENT_INDICATOR = "dyldreadonly"
_DYLD_SELECT_MODULE_RE = re.compile(
    "Apple DYLD cache.*select module.*", re.IGNORECASE
)

# ARM64 BRK #1 instruction encoding
_ARM64_BRK_1_OPCODE = b"\x20\x00\x20\xd4"


def _initialize_dscu() -> ty.Optional[idaapi.netnode]:
    """Initialize the DSCU plugin interface."""
    try:
        dscu_node = idaapi.netnode("$ dscu")
        if not ida_netnode.exist(dscu_node):
            logger.warning("DSCU netnode doesn't exists")
            return None
        return dscu_node
    except Exception as ex:
        logger.warning("Failed to initialize DSCU plugin", exc_info=ex)
        return None


def _load_segment(dscu_node: idaapi.netnode, addr: int) -> None:
    """Load a segment at the given address using DSCU plugin."""
    try:
        dscu_node.altset(3, addr)
        idaapi.load_and_run_plugin("dscu", 2)
    except Exception as ex:
        logger.warning(
            "Failed to load segment",
            address=f"{addr:016x}",
            exc_info=ex,
        )


def _remove_brk_functions() -> None:
    """Remove ARM64 functions that only contain a BRK #1 instruction."""
    # Only process ARM64 binaries
    if not (
        ida_ida.inf_get_procname().lower() == "arm" and ida_ida.inf_is_64bit()
    ):
        return

    logger.debug("Scanning for BRK #1 functions")

    # Find all functions that only contain BRK #1
    brk_funcs = []
    for start_ea in idautils.Functions():
        func = ida_funcs.get_func(start_ea)
        if func is None:
            continue

        # Check if function is exactly 4 bytes (single BRK instruction)
        if func.end_ea - func.start_ea != 4:
            continue

        # Check if the bytes match BRK #1 opcode
        if ida_bytes.get_bytes(start_ea, 4) == _ARM64_BRK_1_OPCODE:
            brk_funcs.append(start_ea)

    # Delete all BRK #1 functions
    for brk_func in brk_funcs:
        ida_funcs.del_func(brk_func)

    if brk_funcs:
        logger.info("Removed BRK #1 functions", count=len(brk_funcs))


class _CollectEmptyDirs(ida_dirtree.dirtree_visitor_t):
    """Visitor class to collect empty directories from IDA's directory tree."""

    def __init__(self, funcs_tree: ida_dirtree.dirtree_t):
        ida_dirtree.dirtree_visitor_t.__init__(self)
        self.empty_dirs: list[str] = []
        self.funcs_tree = funcs_tree

    def visit(
        self, c: ida_dirtree.dirtree_cursor_t, de: ida_dirtree.direntry_t
    ) -> int:
        """Visit a directory entry and collect if empty."""
        is_dir = ida_dirtree.dirtree_t.isdir(de)  # type: ignore
        if is_dir and self.funcs_tree.get_dir_size(de.idx) == 0:
            self.empty_dirs.append(self.funcs_tree.get_abspath(c))
        return 0


@dataclass
class _ImportedFunction:
    """Information about an imported function from a loaded segment."""

    address: int
    flags: int
    name: ty.Optional[str]
    type_str: ty.Optional[str]


@dataclass
class _ImportedData:
    """Information about imported data from a loaded segment."""

    address: int
    data: bytes
    flags: int
    name: ty.Optional[str]


@dataclass
class _ImportedSegment:
    """A segment containing imported functions and data."""

    segm_start: int
    segm_end: int
    segm_name: str
    perm: int
    functions: dict[int, _ImportedFunction]
    data: dict[int, _ImportedData]


class PreprocessingTask(ForegroundTask):
    """
    Foreground task that loads external segments referenced by errors.

    This task uses the DSCU plugin to dynamically load segments that are
    referenced but not mapped in IDA. It extracts function prototypes and
    data, then recreates minimal sparse segments with this information.
    """

    def _run(self):
        try:
            try:
                self._preprocess_dyld_repair_memory_errors()
            except Exception as ex:
                logger.warning("Failed repairing memory errors", exc_info=ex)

            try:
                _remove_brk_functions()
            except Exception as ex:
                logger.warning("Failed removing brk functions", exc_info=ex)

            try:
                from swift_tools.enrichments import run_global_enrichments  # type: ignore

                logger.info("Running ST")
                run_global_enrichments()
            except ImportError:
                logger.info("Skipped running ST (not found)")
            except Exception as ex:
                logger.warning("Failed removing brk functions", exc_info=ex)

            logger.info("Preprocessing task completed successfully")
        finally:
            self._mark_ready_for_analysis()

    def _preprocess_dyld_repair_memory_errors(self):
        # Only process Dyld selected modules
        if not _DYLD_SELECT_MODULE_RE.match(ida_loader.get_file_type_name()):
            return

        # Initialize DSCU plugin interface
        dscu_node = _initialize_dscu()
        if dscu_node is None:
            logger.warning("DSCU plugin not available, skipping preprocessing")
            return

        # Find all error operands that might need segment loading
        error_operand_to_eas = self._find_error_operands()
        if not error_operand_to_eas:
            logger.info("No error operands found, preprocessing complete")
            return

        total_operands = len(error_operand_to_eas)
        logger.info("Found error operands to process", count=total_operands)

        # Start wait box with progress tracking
        self._wait_box.start_new_task(
            _PREPROCESSING_WAITBOX_TEXT,
            items=total_operands,
        )

        # Load segments and extract information
        # Auto-dismiss any warning dialogs that appear during segment loading
        with auto_dismiss_warnings():
            imported_segments = self._load_and_process_segments(
                dscu_node, error_operand_to_eas
            )

        total_functions = sum(len(seg.functions) for seg in imported_segments)
        total_data = sum(len(seg.data) for seg in imported_segments)

        logger.info(
            "Segment loading complete",
            segments=len(imported_segments),
            functions=total_functions,
            data_items=total_data,
        )

        # Remove empty directories created during segment loading
        self._remove_empty_directories()

        # Recreate sparse segments with extracted information
        self._recreate_sparse_segments(imported_segments)

    def _find_error_operands(self) -> dict[int, list[int]]:
        """
        Find all error operands in the database.

        Returns:
            Mapping from error operand address to list of error locations.
        """
        logger.debug("Scanning for error operands")

        # Find all error addresses
        error_eas: list[int] = []
        cur_ea = 0
        while cur_ea != idaapi.BADADDR:
            cur_ea, _ = ida_search.find_error(cur_ea, ida_search.SEARCH_DOWN)  # type: ignore
            if cur_ea == idaapi.BADADDR:
                break
            error_eas.append(cur_ea)

        logger.debug("Found error addresses", count=len(error_eas))

        # Parse error operands from disassembly
        error_operand_to_eas: dict[int, list[int]] = defaultdict(list)
        for error_ea in error_eas:
            disasm_line = ida_lines.generate_disasm_line(error_ea)
            regex_result = _ERROR_OPERAND_RE.search(disasm_line)
            if regex_result is None:
                continue

            matching_err_operand = regex_result.groups()[0]
            if not matching_err_operand.startswith("0x"):
                continue

            try:
                error_operand = int(matching_err_operand, 16)
                if error_operand >= _MIN_SEGMENT_ADDRESS:
                    error_operand_to_eas[error_operand].append(error_ea)
            except ValueError:
                logger.debug(
                    "Failed to parse error operand",
                    operand=matching_err_operand,
                )

        return error_operand_to_eas

    def _should_skip_error_operand(self, ea: int) -> bool:
        """
        Check if an error operand should be skipped.

        Args:
            ea: The error operand address to check.

        Returns:
            True if the operand should be skipped, False otherwise.
        """
        # Skip if address is too low
        if ea < _MIN_SEGMENT_ADDRESS:
            return True

        # Skip if already mapped
        if idaapi.is_mapped(ea):
            return True

        return False

    def _identify_newly_loaded_addresses(
        self, error_operand: int, error_operands: set[int]
    ) -> set[int]:
        """
        Identify which addresses were mapped after a segment load.

        Args:
            error_operand: The operand that triggered the segment load.
            error_operands: Set of all remaining error operands.

        Returns:
            Set of addresses that are now mapped.
        """
        return {
            ea
            for ea in [error_operand] + list(error_operands)
            if idaapi.is_mapped(ea)
        }

    def _get_segment_permissions(self, seg, segm_name: str) -> int:
        """
        Get segment permissions, applying fallback logic if needed.

        Args:
            seg: The IDA segment object.
            segm_name: The segment name.

        Returns:
            The segment permissions flags.
        """
        perm = seg.perm
        # Apply fallback for dyld readonly segments with missing permissions
        if perm == 0:
            if _READONLY_SEGMENT_INDICATOR in segm_name:
                perm = ida_segment.SEGPERM_EXEC | ida_segment.SEGPERM_READ
        return perm

    def _get_or_create_segment_entry(
        self, ea: int, segments_dict: dict[int, _ImportedSegment]
    ) -> ty.Optional[int]:
        """
        Get segment metadata and create entry in dict if it doesn't exist.

        Args:
            ea: Address within the segment.
            segments_dict: Dictionary mapping segment start addresses to ImportedSegment objects.

        Returns:
            The segment start address, or None if segment not found.
        """
        seg = ida_segment.getseg(ea)
        if not seg:
            return None

        segm_start = seg.start_ea

        # Create segment entry if it doesn't exist
        if segm_start not in segments_dict:
            segm_name = ida_segment.get_segm_name(seg)
            perm = self._get_segment_permissions(seg, segm_name)

            segments_dict[segm_start] = _ImportedSegment(
                segm_start=segm_start,
                segm_end=seg.end_ea,
                segm_name=segm_name,
                perm=perm,
                functions={},
                data={},
            )

        return segm_start

    def _extract_and_store_address_info(
        self,
        ea: int,
        segm_start: int,
        segments_dict: dict[int, _ImportedSegment],
    ) -> None:
        """
        Extract function or data info from an address and store in segment.

        Args:
            ea: The address to extract information from.
            segm_start: The start address of the containing segment.
            segments_dict: Dictionary of imported segments.
        """
        # Extract and store function or data info
        if ida_bytes.is_func(ida_bytes.get_full_flags(ea)):
            func_info = self._extract_function_info(ea)
            if func_info:
                segments_dict[segm_start].functions[ea] = func_info
        else:
            data_info = self._extract_data_info(ea)
            if data_info:
                segments_dict[segm_start].data[ea] = data_info

    def _process_loaded_addresses(
        self,
        newly_loaded: set[int],
        segments_dict: dict[int, _ImportedSegment],
    ) -> None:
        """
        Process all newly loaded addresses, extracting their information.

        Args:
            newly_loaded: Set of addresses that were just loaded.
            segments_dict: Dictionary of imported segments (will be modified).
        """
        for ea in newly_loaded:
            # Get segment information and create entry if needed
            segm_start = self._get_or_create_segment_entry(ea, segments_dict)
            if segm_start is None:
                self._wait_box.mark_items_complete(1)
                continue

            # Extract and store the address information
            self._extract_and_store_address_info(ea, segm_start, segments_dict)

            self._wait_box.mark_items_complete(1)

    def _load_and_process_segments(
        self,
        dscu_node: idaapi.netnode,
        error_operand_to_eas: dict[int, list[int]],
    ) -> list[_ImportedSegment]:
        """
        Iteratively load segments for error operands and extract information.

        Args:
            dscu_node: The DSCU plugin netnode interface.
            error_operand_to_eas: Mapping from operand addresses to error locations.

        Returns:
            List of imported segments with their functions and data.
        """
        # Track segments by their start address
        segments_dict: dict[int, _ImportedSegment] = {}

        error_operands = set(error_operand_to_eas.keys())
        total_count = len(error_operands)

        logger.info("Processing error operands", total=total_count)

        while error_operands:
            error_operand = error_operands.pop()

            # Skip if address is too low or already mapped
            if self._should_skip_error_operand(error_operand):
                continue

            # Load segment using DSCU plugin
            logger.debug(
                "Loading segment",
                address=f"{error_operand:016x}",
                remaining=len(error_operands),
            )

            _load_segment(dscu_node, error_operand)

            # Check which operands are now mapped
            newly_loaded = self._identify_newly_loaded_addresses(
                error_operand, error_operands
            )

            if not newly_loaded:
                self._wait_box.mark_items_complete(1)
                ida_tasks.execute_queued_tasks_sync()
                continue

            # Analyze newly loaded segment
            self._analyze_loaded_segment(
                error_operand, newly_loaded, error_operand_to_eas
            )

            error_operands -= newly_loaded

            # Extract information from newly loaded addresses
            try:
                self._process_loaded_addresses(newly_loaded, segments_dict)
            finally:
                # Delete the loaded segment to save memory
                self._delete_segment(error_operand)

            ida_tasks.execute_queued_tasks_sync()

        return list(segments_dict.values())

    def _analyze_loaded_segment(
        self,
        segment_base: int,
        newly_loaded: set[int],
        error_operand_to_eas: dict[int, list[int]],
    ) -> None:
        """Analyze a newly loaded segment."""
        # Mark error locations for analysis
        for loaded_operand in newly_loaded:
            for au_ea_mark in error_operand_to_eas[loaded_operand]:
                ida_auto.auto_mark(au_ea_mark, ida_auto.AU_USED)

        # Run analysis and wait for completion
        segm_start = idc.get_segm_start(segment_base)
        segm_end = idc.get_segm_end(segment_base)

        if segm_start != idaapi.BADADDR and segm_end != idaapi.BADADDR:
            ida_auto.plan_and_wait(segm_start, segm_end)
            ida_auto.auto_wait()

    def _extract_function_info(self, ea: int) -> ty.Optional[_ImportedFunction]:
        """Extract information about a function at the given address."""
        try:
            flags = ida_bytes.get_full_flags(ea)
            name = (
                None
                if ida_bytes.has_dummy_name(flags)
                else ida_name.get_name(ea)
            )

            # Try to get function prototype
            func_prototype = ida_typeinf.print_type(ea, 0)
            if func_prototype is None:
                # Try decompiling first
                try:
                    ida_hexrays.decompile(ea)
                    func_prototype = ida_typeinf.print_type(ea, 0)
                except Exception:
                    pass

            if func_prototype:
                logger.debug(
                    "Extracted function",
                    address=f"{ea:016x}",
                    type=func_prototype,
                )

            return _ImportedFunction(
                address=ea,
                flags=flags,
                name=name,
                type_str=func_prototype,
            )
        except Exception as ex:
            logger.warning(
                "Failed to extract function info",
                address=f"{ea:016x}",
                exc_info=ex,
            )
            return None

    def _extract_data_info(self, ea: int) -> ty.Optional[_ImportedData]:
        """Extract information about data at the given address."""
        try:
            flags = ida_bytes.get_full_flags(ea)
            data_len = ida_bytes.get_item_size(ea)
            data = ida_bytes.get_bytes(ea, data_len)

            if data is None:
                return None

            name = (
                None
                if ida_bytes.has_dummy_name(flags)
                else ida_name.get_name(ea)
            )

            logger.debug(
                "Extracted data",
                address=f"{ea:016x}",
                size=data_len,
            )

            return _ImportedData(
                address=ea,
                data=data,
                flags=flags,
                name=name,
            )
        except Exception as ex:
            logger.warning(
                "Failed to extract data info",
                address=f"{ea:016x}",
                exc_info=ex,
            )
            return None

    def _delete_segment(self, addr: int) -> None:
        """Delete a segment to free memory."""
        try:
            segm_start = idc.get_segm_start(addr)
            if segm_start != idaapi.BADADDR:
                ida_segment.del_segm(segm_start, ida_segment.SEGMOD_KILL)
        except Exception as ex:
            logger.debug(
                "Failed to delete segment",
                address=f"{addr:016x}",
                exc_info=ex,
            )

    def _remove_empty_directories(self) -> None:
        """Remove empty directories from the Functions tree."""
        try:
            # Get the Functions tree
            funcs_tree = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)  # type: ignore
            if not funcs_tree:
                logger.debug("Functions tree not available")
                return

            # Collect empty directories
            collector = _CollectEmptyDirs(funcs_tree)
            funcs_tree.traverse(collector)

            # Remove collected empty directories
            for empty_dir in collector.empty_dirs:
                try:
                    funcs_tree.rmdir(empty_dir)
                except Exception as ex:
                    logger.debug(
                        "Failed to remove empty directory",
                        path=empty_dir,
                        exc_info=ex,
                    )

            if collector.empty_dirs:
                logger.info(
                    "Removed empty directories from Functions tree",
                    count=len(collector.empty_dirs),
                )
        except Exception as ex:
            logger.warning(
                "Failed to remove empty directories",
                exc_info=ex,
            )

    def _recreate_sparse_segments(
        self, imported_segments: list[_ImportedSegment]
    ) -> None:
        """Recreate sparse segments with extracted information."""
        total_functions = sum(len(seg.functions) for seg in imported_segments)
        total_data = sum(len(seg.data) for seg in imported_segments)

        logger.info(
            "Recreating sparse segments",
            segment_count=len(imported_segments),
            functions=total_functions,
            data_items=total_data,
        )

        for segment in imported_segments:
            try:
                # Determine segment class: use XTRN for functions-only, DATA otherwise
                segment_class = "XTRN" if not segment.data else "DATA"

                # Create segment if it doesn't exist
                if idc.get_segm_start(segment.segm_start) == idaapi.BADADDR:
                    ida_segment.add_segm(
                        0,
                        segment.segm_start,
                        segment.segm_end,
                        segment.segm_name,
                        segment_class,
                        ida_segment.ADDSEG_SPARSE,
                    )
                    seg = ida_segment.getseg(segment.segm_start)
                    if seg:
                        seg.perm = segment.perm
                        ida_segment.update_segm(seg)

                    # Mark this segment to be excluded from upload
                    self._ctx.model.sections_excluded_from_upload.set_sync(
                        segment.segm_start, True
                    )

                    logger.debug(
                        "Created sparse segment",
                        start=f"{segment.segm_start:016x}",
                        end=f"{segment.segm_end:016x}",
                        name=segment.segm_name,
                        class_=segment_class,
                        perm=segment.perm,
                    )

                # Populate data items in the segment
                for data_ea, data_info in segment.data.items():
                    try:
                        if data_info.name:
                            idc.set_name(
                                data_ea, data_info.name, ida_name.SN_FORCE
                            )
                        ida_bytes.put_bytes(data_ea, data_info.data)

                        logger.debug(
                            "Added data to segment",
                            address=f"{data_ea:016x}",
                            name=data_info.name,
                        )
                    except Exception as ex:
                        logger.warning(
                            "Failed to add data to segment",
                            address=f"{data_ea:016x}",
                            exc_info=ex,
                        )

                # Populate functions in the segment
                for func_ea, func_info in segment.functions.items():
                    try:
                        if func_info.name:
                            idc.set_name(
                                func_ea, func_info.name, ida_name.SN_FORCE
                            )
                        if func_info.type_str:
                            idc.SetType(func_ea, func_info.type_str)

                        logger.debug(
                            "Added function to segment",
                            address=f"{func_ea:016x}",
                            name=func_info.name,
                            type=func_info.type_str,
                        )
                    except Exception as ex:
                        logger.warning(
                            "Failed to add function to segment",
                            address=f"{func_ea:016x}",
                            exc_info=ex,
                        )

            except Exception as ex:
                logger.warning(
                    "Failed to recreate segment",
                    start=f"{segment.segm_start:016x}",
                    exc_info=ex,
                )

    def _mark_ready_for_analysis(self) -> None:
        """Mark the binary as ready for analysis."""
        # Preprocessing complete (or skipped), ready for upload
        self._ctx.model.ready_for_analysis.set_sync(True)
        self._ctx.model.notify_update()
