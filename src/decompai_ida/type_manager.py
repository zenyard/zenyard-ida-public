"""
Type manager for tracking and managing struct types in IDA's type library.

This module ensures that only struct types actually used by parameter/return value
inferences (directly or indirectly through nested structs) are registered in IDA's
type library.
"""

import re
import typing as ty
from inspect import cleandoc

import ida_dirtree
import ida_typeinf

from decompai_client import StructDefinition
from decompai_ida import ida_tasks, logger
from decompai_ida.struct_generator import (
    generate_struct_declaration_with_renames,
)
from decompai_ida.lvars import apply_func_types_batch_sync

if ty.TYPE_CHECKING:
    from decompai_ida.model import Model
    from decompai_ida.wait_box import WaitBox

# Key used in function_struct_usage dict for return type
_RETURN_KEY = "return"

# Pattern for substituting struct names in type strings (word boundary matching)
_STRUCT_NAME_PATTERN = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")

_ZENYARD_DIR = "Zenyard"

_RECONCILE_WAITBOX_TEXT = cleandoc("""
    Zenyard is updating type definitions — almost done
""")

_APPLY_TYPES_WAITBOX_TEXT = cleandoc("""
    Zenyard is applying updated type definitions — almost done
""")


def _compute_effective_names(
    required_struct_ids: set[str],
    definitions: dict[str, StructDefinition],
    *,
    taken_names: set[str],
) -> dict[str, str]:
    """
    Compute effective names for structs, adding suffix for collisions.

    Handles two kinds of collisions:
    - Multiple required structs share the same name: all get a struct_id suffix.
    - A struct's name is already taken in IDA by a user-created type
      (passed via taken_names): that struct gets a struct_id suffix.

    Returns: mapping of struct_id -> effective_name
    """
    # Group struct_ids by their original name
    name_to_ids = dict[str, list[str]]()
    for struct_id in required_struct_ids:
        struct_def = definitions.get(struct_id)
        if struct_def:
            name_to_ids.setdefault(struct_def.name, []).append(struct_id)

    # Compute effective names
    effective_names = dict[str, str]()
    for name, ids in name_to_ids.items():
        if len(ids) == 1 and name not in taken_names:
            # No collision
            effective_names[ids[0]] = name
        else:
            # Collision - add suffix from struct_id
            for struct_id in ids:
                effective_names[struct_id] = f"{name}_{struct_id[:8]}"

    return effective_names


def _substitute_struct_names(
    type_str: str,
    name_substitutions: dict[str, str],
) -> str:
    """
    Substitute struct names in a C type string.

    Uses word boundary matching to avoid partial replacements.

    Example: "Config*" -> "Config_abc123*" if Config was renamed
    """
    if not name_substitutions:
        return type_str

    def replace_match(match: re.Match[str]) -> str:
        name = match.group(1)
        return name_substitutions.get(name, name)

    return _STRUCT_NAME_PATTERN.sub(replace_match, type_str)


def register_struct_definition_sync(
    struct_def: StructDefinition, *, model: "Model"
) -> None:
    """
    Store struct definition and compute its dependencies.

    Does NOT immediately add to IDA's type library - reconcile_type_library_sync
    handles that.
    """
    # Store the definition
    model.struct_definitions.set_sync(struct_def.id, struct_def)

    # Compute and store dependencies from field types
    dep_ids = [
        field.struct_id
        for field in struct_def.field_definitions
        if field.struct_id is not None
    ]
    model.struct_dependencies.set_sync(struct_def.id, dep_ids)

    logger.debug(
        "Registered struct definition",
        struct_id=struct_def.id,
        struct_name=struct_def.name,
    )


def set_parameter_struct_sync(
    address: int,
    parameter_index: int,
    struct_id: ty.Optional[str],
    *,
    model: "Model",
) -> None:
    """
    Set the struct_id used by a parameter at the given address.

    Pass struct_id=None to clear the struct usage for this parameter.
    """
    usage = model.function_struct_usage.get_sync(address) or {}
    key = str(parameter_index)

    if struct_id is not None:
        usage[key] = struct_id
    elif key in usage:
        del usage[key]

    _update_struct_usage(address, usage, model=model)


def set_return_struct_sync(
    address: int,
    struct_id: ty.Optional[str],
    *,
    model: "Model",
) -> None:
    """
    Set the struct_id used by the return type at the given address.

    Pass struct_id=None to clear the struct usage for this return type.
    """
    usage = model.function_struct_usage.get_sync(address) or {}

    if struct_id is not None:
        usage[_RETURN_KEY] = struct_id
    elif _RETURN_KEY in usage:
        del usage[_RETURN_KEY]

    _update_struct_usage(address, usage, model=model)


def _update_struct_usage(
    address: int, usage: dict[str, str], *, model: "Model"
) -> None:
    model.function_struct_usage.set_sync(address, usage if usage else None)


def _collect_directly_used_structs_sync(*, model: "Model") -> set[str]:
    """
    Collect all struct_ids directly referenced by parameter/return types.

    Iterates over all function_struct_usage entries to find directly used structs.
    """
    used = set[str]()

    for address in model.function_struct_usage.keys_sync():
        usage = model.function_struct_usage.get_sync(address)
        if usage:
            for struct_id in usage.values():
                used.add(struct_id)

    return used


def compute_required_structs_sync(*, model: "Model") -> set[str]:
    """
    Return all struct_ids that should exist in IDA's type library.

    Computes transitive closure of directly used structs plus their dependencies.
    """
    required = set[str]()
    directly_used = _collect_directly_used_structs_sync(model=model)
    to_visit = set(directly_used)

    while to_visit:
        struct_id = to_visit.pop()
        if struct_id in required:
            continue
        required.add(struct_id)

        # Add dependencies (nested structs)
        for dep_id in model.struct_dependencies.get_sync(struct_id) or []:
            if dep_id not in required:
                to_visit.add(dep_id)

    return required


def _topological_sort(
    struct_ids: set[str], dependencies: dict[str, list[str]]
) -> list[str]:
    """
    Sort structs so dependencies come before dependents.

    Handles cycles by breaking them (cycles shouldn't happen with proper struct
    definitions, but we handle them gracefully).
    """
    result = list[str]()
    visiting = set[str]()
    visited = set[str]()

    def visit(struct_id: str) -> None:
        if struct_id in visited:
            return
        if struct_id in visiting:
            # Cycle detected - skip to break cycle
            return

        visiting.add(struct_id)

        # Visit dependencies first
        deps = dependencies.get(struct_id, [])
        for dep_id in deps:
            if dep_id in struct_ids:
                visit(dep_id)

        visiting.discard(struct_id)
        visited.add(struct_id)
        result.append(struct_id)

    for struct_id in struct_ids:
        visit(struct_id)

    return result


def _move_struct_to_zenyard_dir_sync(effective_name: str) -> None:
    dirtree = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_LOCAL_TYPES)  # type: ignore[attr-defined]
    err = dirtree.mkdir(_ZENYARD_DIR)
    if err not in (ida_dirtree.DTE_OK, ida_dirtree.DTE_ALREADY_EXISTS):  # type: ignore[attr-defined]
        logger.warning("Failed to create Zenyard dir in local types", error=err)
        return
    err = dirtree.rename(effective_name, f"{_ZENYARD_DIR}/{effective_name}")
    if err != ida_dirtree.DTE_OK:  # type: ignore[attr-defined]
        logger.warning(
            "Failed to move struct to Zenyard dir",
            effective_name=effective_name,
            error=err,
        )


def _add_struct_to_ida_sync(
    struct_id: str,
    effective_names: dict[str, str],
    definitions: dict[str, StructDefinition],
    *,
    model: "Model",
) -> bool:
    """
    Add a struct to IDA's type library.

    Args:
        struct_id: The ID of the struct to add
        effective_names: Mapping of struct_id -> effective_name for resolving
            field type substitutions and determining this struct's name in IDA
        definitions: Mapping of struct_id -> StructDefinition for looking up
            struct definitions and original names

    Returns True if successful, False otherwise.
    """
    struct_def = definitions.get(struct_id)
    effective_name = effective_names.get(struct_id)

    if struct_def is None or effective_name is None:
        logger.warning(
            "Cannot add struct to IDA - definition or effective name not found",
            struct_id=struct_id,
        )
        return False

    try:
        struct_decl = generate_struct_declaration_with_renames(
            struct_def, effective_name, effective_names, definitions
        )
        new_tinfo = ida_typeinf.tinfo_t()
        if (
            ida_typeinf.parse_decl(
                new_tinfo,
                ida_typeinf.get_idati(),  # type: ignore
                struct_decl,
                ida_typeinf.PT_SIL,
            )
            is None
        ):
            logger.warning(
                "Failed to parse struct declaration",
                struct_id=struct_id,
                struct_name=struct_def.name,
                effective_name=effective_name,
            )
            return False

        new_tinfo.set_named_type(None, effective_name)  # type: ignore
        _move_struct_to_zenyard_dir_sync(effective_name)

        # Track what effective_name was used for this struct
        model.registered_struct_names.set_sync(struct_id, effective_name)

        logger.debug(
            "Added struct to IDA type library",
            struct_id=struct_id,
            struct_name=struct_def.name,
            effective_name=effective_name,
        )
        return True

    except Exception as ex:
        logger.warning(
            "Error adding struct to IDA",
            struct_id=struct_id,
            exc_info=ex,
        )
        return False


def _remove_struct_from_ida_sync(
    struct_id: str,
    effective_name: str,
    *,
    model: "Model",
) -> bool:
    """
    Remove a struct from IDA's type library.

    Args:
        struct_id: The ID of the struct to remove
        effective_name: The name the struct was registered under in IDA

    Returns True if successful, False otherwise.
    """
    # Remove from registered_struct_names regardless of whether delete succeeds
    model.registered_struct_names.set_sync(struct_id, None)

    try:
        til = ida_typeinf.get_idati()
        ordinal = ida_typeinf.get_type_ordinal(til, effective_name)

        if ordinal != 0:
            ida_typeinf.del_numbered_type(til, ordinal)
            logger.debug(
                "Removed struct from IDA type library",
                struct_id=struct_id,
                effective_name=effective_name,
            )

        return True

    except Exception as ex:
        logger.warning(
            "Error removing struct from IDA",
            struct_id=struct_id,
            effective_name=effective_name,
            exc_info=ex,
        )
        return False


def _reregister_struct_in_ida_sync(
    struct_id: str,
    old_effective_name: str,
    effective_names: dict[str, str],
    definitions: dict[str, StructDefinition],
    *,
    model: "Model",
) -> bool:
    """
    Re-register a struct in IDA's type library with a new name.

    Updates the struct in place using its original ordinal rather than
    removing and re-adding it.

    Args:
        struct_id: The ID of the struct to re-register
        old_effective_name: The name the struct was previously registered under
        effective_names: Mapping of struct_id -> effective_name for resolving
            field type substitutions and determining this struct's new name
        definitions: Mapping of struct_id -> StructDefinition for looking up
            struct definitions and original names

    Returns True if successful, False otherwise.
    """
    struct_def = definitions.get(struct_id)
    new_effective_name = effective_names.get(struct_id)

    if struct_def is None or new_effective_name is None:
        logger.warning(
            "Cannot re-register struct - definition or effective name not found",
            struct_id=struct_id,
        )
        return False

    try:
        til = ida_typeinf.get_idati()
        original_ordinal = ida_typeinf.get_type_ordinal(til, old_effective_name)

        if original_ordinal == 0:
            logger.warning(
                "Cannot re-register struct - not found in type library",
                struct_id=struct_id,
                old_effective_name=old_effective_name,
            )
            return False

        struct_decl = generate_struct_declaration_with_renames(
            struct_def, new_effective_name, effective_names, definitions
        )
        new_tinfo = ida_typeinf.tinfo_t()
        if (
            ida_typeinf.parse_decl(
                new_tinfo,
                til,  # type: ignore
                struct_decl,
                ida_typeinf.PT_SIL,
            )
            is None
        ):
            logger.warning(
                "Failed to parse struct declaration for re-registration",
                struct_id=struct_id,
                struct_name=struct_def.name,
                new_effective_name=new_effective_name,
            )
            return False

        # Update in place using the original ordinal
        new_tinfo.set_numbered_type(
            None,  # type: ignore
            original_ordinal,
            ida_typeinf.NTF_REPLACE,
            new_effective_name,
        )

        # Update tracked effective name
        model.registered_struct_names.set_sync(struct_id, new_effective_name)

        logger.debug(
            "Re-registered struct in IDA type library",
            struct_id=struct_id,
            struct_name=struct_def.name,
            old_effective_name=old_effective_name,
            new_effective_name=new_effective_name,
        )
        return True

    except Exception as ex:
        logger.warning(
            "Error re-registering struct in IDA",
            struct_id=struct_id,
            exc_info=ex,
        )
        return False


def set_original_type_annotation_sync(
    address: int,
    key: str,
    original_annotation: str,
    *,
    model: "Model",
) -> None:
    """
    Store original type annotation for applying/re-applying.

    Args:
        address: Function address
        key: Parameter index string ("0", "1", etc.) or "return"
        original_annotation: The original type annotation string
        model: The model
    """
    annotations = (
        model.function_original_type_annotations.get_sync(address) or {}
    )
    annotations[key] = original_annotation
    model.function_original_type_annotations.set_sync(address, annotations)


def _apply_types_batched_sync(
    struct_ids: set[str],
    *,
    definitions: dict[str, StructDefinition],
    model: "Model",
    wait_box: "WaitBox",
) -> None:
    """
    Apply type annotations for all functions using the given structs, batched
    by address so each function gets a single apply_tinfo call.
    """
    # Build name substitutions for all structs.
    name_subs = dict[str, dict[str, str]]()
    for struct_id in struct_ids:
        struct_def = definitions.get(struct_id)
        effective_name = model.registered_struct_names.get_sync(struct_id)
        if not struct_def or not effective_name:
            continue
        if struct_def.name != effective_name:
            name_subs[struct_id] = {struct_def.name: effective_name}
        else:
            name_subs[struct_id] = {}

    # Collect all type changes grouped by address.
    # Key: address, Value: dict of key -> (struct_id, annotation)
    pending = dict[int, dict[str, tuple[str, str]]]()
    for address in model.function_struct_usage.keys_sync():
        usage = model.function_struct_usage.get_sync(address)
        if not usage:
            continue
        annotations = (
            model.function_original_type_annotations.get_sync(address) or {}
        )
        for key, struct_id in usage.items():
            if struct_id not in struct_ids:
                continue
            if struct_id not in name_subs:
                continue
            original_annotation = annotations.get(key)
            if not original_annotation:
                continue
            new_annotation = _substitute_struct_names(
                original_annotation, name_subs[struct_id]
            )
            pending.setdefault(address, {})[key] = (struct_id, new_annotation)

    # Apply batched per address.
    if not pending:
        return
    wait_box.start_new_task(_APPLY_TYPES_WAITBOX_TEXT, items=len(pending))
    for address, changes in pending.items():
        parameter_types = dict[int, str]()
        return_type: ty.Optional[str] = None
        for key, (struct_id, annotation) in changes.items():
            if key == _RETURN_KEY:
                return_type = annotation
            else:
                parameter_types[int(key)] = annotation

        try:
            apply_func_types_batch_sync(
                address,
                parameter_types=parameter_types,
                return_type=return_type,
            )
            logger.debug(
                "Applied types for function",
                address=address,
                parameter_types=parameter_types,
                return_type=return_type,
            )
        except Exception as ex:
            logger.warning(
                "Error applying types for function",
                address=address,
                exc_info=ex,
            )
        wait_box.mark_items_complete(1)
        ida_tasks.execute_queued_tasks_sync()


def reconcile_type_library_sync(*, model: "Model", wait_box: "WaitBox") -> None:
    """
    Compute required structs and sync IDA's type library.

    1. Collect all directly used structs
    2. Compute transitive closure (add dependencies)
    3. Compute effective names (handling collisions by adding struct_id suffix)
    4. Remove unused structs from IDA (in reverse dependency order)
    5. Re-register structs whose effective name changed (in place, preserving ordinal)
    6. Add missing structs to IDA (in dependency order)
    """
    required = compute_required_structs_sync(model=model)
    registered = model.registered_struct_names.keys_sync()

    needed_ids = required | registered
    definitions = {
        sid: d
        for sid in needed_ids
        if (d := model.struct_definitions.get_sync(sid)) is not None
    }
    dependencies = {
        sid: (model.struct_dependencies.get_sync(sid) or [])
        for sid in needed_ids
    }

    # Compute effective names for all required structs, resolving collisions
    # with both other plugin structs and user-created types in IDA.
    our_registered_names = {
        name
        for sid in registered
        if (name := model.registered_struct_names.get_sync(sid)) is not None
    }
    til = ida_typeinf.get_idati()
    taken_names = {
        struct_def.name
        for sid in required
        if (struct_def := definitions.get(sid)) is not None
        and ida_typeinf.get_type_ordinal(til, struct_def.name) != 0
        and struct_def.name not in our_registered_names
    }
    effective_names = _compute_effective_names(
        required, definitions, taken_names=taken_names
    )

    # Determine what needs to change
    to_add = required - registered
    to_remove = registered - required

    # Check for structs that need re-registration (effective name changed)
    to_reregister = set[str]()
    for struct_id in required & registered:
        old_effective = model.registered_struct_names.get_sync(struct_id)
        new_effective = effective_names.get(struct_id)
        if old_effective and new_effective and old_effective != new_effective:
            to_reregister.add(struct_id)

    if not to_add and not to_remove and not to_reregister:
        return

    # Pre-compute stale dependents before the loops so we can include them in
    # the total item count for progress tracking.
    changed_deps = to_add | to_reregister
    stale_dependents = set[str]()
    for struct_id in (required & registered) - to_reregister:
        deps = dependencies.get(struct_id, [])
        if any(dep_id in changed_deps for dep_id in deps):
            stale_dependents.add(struct_id)

    total = (
        len(to_remove)
        + len(to_reregister)
        + len(to_add)
        + len(stale_dependents)
    )
    wait_box.start_new_task(_RECONCILE_WAITBOX_TEXT, items=total)

    def _tick():
        wait_box.mark_items_complete(1)
        ida_tasks.execute_queued_tasks_sync()

    # Remove unused structs in reverse order (dependents first)
    if to_remove:
        for struct_id in reversed(_topological_sort(to_remove, dependencies)):
            old_effective = model.registered_struct_names.get_sync(struct_id)
            if old_effective:
                _remove_struct_from_ida_sync(
                    struct_id, old_effective, model=model
                )
            _tick()

    # Re-register structs whose effective name changed (in place, preserving ordinal)
    if to_reregister:
        for struct_id in _topological_sort(to_reregister, dependencies):
            old_effective = model.registered_struct_names.get_sync(struct_id)
            if old_effective:
                _reregister_struct_in_ida_sync(
                    struct_id,
                    old_effective,
                    effective_names,
                    definitions,
                    model=model,
                )
            _tick()

    # Add new structs in dependency order (dependencies first)
    if to_add:
        for struct_id in _topological_sort(to_add, dependencies):
            _add_struct_to_ida_sync(
                struct_id,
                effective_names,
                definitions,
                model=model,
            )
            _tick()

    # Re-register already-registered structs whose dependencies were just added
    # or renamed. These structs may have stale field type names in IDA (e.g. a
    # forward-declared "RefTarget" that was never resolved, now replaced by
    # "RefTarget_inner_aa"). Must run after to_add so the new names exist in IDA.
    if stale_dependents:
        for struct_id in _topological_sort(stale_dependents, dependencies):
            old_effective = model.registered_struct_names.get_sync(struct_id)
            if old_effective:
                _reregister_struct_in_ida_sync(
                    struct_id,
                    old_effective,
                    effective_names,
                    definitions,
                    model=model,
                )
            _tick()

    # Apply types for all functions using structs that were added or re-registered.
    # Batch all type changes per function into a single apply_tinfo call.
    structs_needing_type_application = to_add | to_reregister | stale_dependents
    if structs_needing_type_application:
        _apply_types_batched_sync(
            structs_needing_type_application,
            definitions=definitions,
            model=model,
            wait_box=wait_box,
        )

    logger.debug(
        "Reconciled type library",
        added=len(to_add),
        removed=len(to_remove),
        reregistered=len(to_reregister),
    )


def substitute_type_annotation_for_struct_sync(
    type_annotation: str,
    struct_id: ty.Optional[str],
    *,
    model: "Model",
    context: ty.Optional[str] = None,
) -> str:
    """
    Substitute struct name in a type annotation to the struct's effective name.

    Handles collision handling: If the struct's name collides with another,
    uses the suffixed effective name.

    Args:
        type_annotation: C type string that references the struct (uses original name)
        struct_id: The struct ID referenced in the type annotation
        model: The model containing struct definitions and registered names
        context: Optional context for logging (e.g., "parameter", "return")

    Returns:
        The type annotation with the struct name substituted to the struct's
        effective name
    """
    if not struct_id:
        return type_annotation

    # Get the struct's name (what's in the type annotation)
    struct_def = model.struct_definitions.get_sync(struct_id)
    if not struct_def:
        return type_annotation
    original_name = struct_def.name

    # Get the effective name the struct is registered under
    effective_name = model.registered_struct_names.get_sync(struct_id)

    if not effective_name or effective_name == original_name:
        # No substitution needed
        return type_annotation

    # Substitute struct's name with effective name
    result = _substitute_struct_names(
        type_annotation, {original_name: effective_name}
    )

    if result != type_annotation:
        logger.debug(
            "Substituted struct name in type annotation",
            context=context,
            original_annotation=type_annotation,
            substituted_annotation=result,
            original_name=original_name,
            effective_name=effective_name,
            struct_id=struct_id,
        )

    return result
