"""
C struct declaration generator.

This module provides utilities for generating C struct declarations from
StructDefinition objects, including proper padding between fields.
"""

import re

import ida_typeinf

from decompai_client import StructDefinition
from decompai_ida import logger

# Pattern for substituting struct names in type strings (word boundary matching)
_STRUCT_NAME_PATTERN = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")


def get_field_size(field_str: str) -> int:
    """
    Get the size of a C type using IDA's type parser.

    Args:
        type_str: C type string (e.g., "int", "char*", "MyStruct")

    Returns:
        Size of the type in bytes

    Raises:
        ValueError: If the type size cannot be determined
    """
    tinfo = ida_typeinf.tinfo_t()
    ida_typeinf.parse_decl(tinfo, None, field_str, ida_typeinf.PT_SIL)  # type: ignore
    tinfo_size = tinfo.get_size()
    if tinfo_size == ida_typeinf.BADSIZE:
        raise ValueError(f"Could not determine size for field: {field_str}")
    return tinfo_size


def format_field(field_type: str, field_name: str) -> str:
    """
    Format a C struct field declaration.

    Args:
        field_type: The type of the field (e.g., "int", "char")
        field_name: The name of the field (may include array notation)

    Returns:
        Formatted field declaration (e.g., "    int field;")

    Raises:
        ValueError: If the field type cannot be parsed
    """
    tif = ida_typeinf.tinfo_t()
    if (
        ida_typeinf.parse_decl(tif, None, f"{field_type};", ida_typeinf.PT_SIL)  # type: ignore
        is None
    ):
        raise ValueError(f"Could not parse field type: {field_type}")
    return f"    {tif._print(field_name)};"  # type: ignore


def format_struct(struct_name: str, fields: list[str]) -> str:
    """
    Format a complete C struct declaration.

    Args:
        struct_name: Name of the struct
        fields: List of formatted field declarations

    Returns:
        Complete struct declaration
    """
    if not fields:
        return f"struct {struct_name} {{}};"

    fields_str = "\n".join(fields)
    return f"struct {struct_name} {{\n{fields_str}\n}};"


def _substitute_field_type(
    field_type: str,
    name_substitutions: dict[str, str],
) -> str:
    """
    Substitute struct names in a field type string.

    Uses word boundary matching to avoid partial replacements.
    """
    if not name_substitutions:
        return field_type

    def replace_match(match: re.Match[str]) -> str:
        name = match.group(1)
        return name_substitutions.get(name, name)

    return _STRUCT_NAME_PATTERN.sub(replace_match, field_type)


def generate_struct_declaration_with_renames(
    struct_def: StructDefinition,
    effective_name: str,
    effective_names: dict[str, str],
    definitions: dict[str, StructDefinition],
) -> str:
    """
    Generate a C struct declaration with renamed struct name and field types.

    This variant allows specifying an effective name for the struct (to handle
    collisions) and substituting struct names in field types.

    Args:
        struct_def: The struct definition containing field definitions
        effective_name: The name to use for the struct (may differ from struct_def.name)
        effective_names: Mapping of struct_id -> effective_name for resolving
            field type substitutions
        definitions: Mapping of struct_id -> StructDefinition for looking up
            original struct names

    Returns:
        C struct declaration string with padding to match field offsets.
        Overlapping fields and fields that fail to generate are skipped with
        a warning logged.
    """
    if not struct_def.field_definitions:
        return format_struct(effective_name, [])

    # Sort fields by offset
    sorted_fields = sorted(
        struct_def.field_definitions, key=lambda f: f.field_offset
    )

    fields = list[str]()
    current_offset = 0
    padding_counter = 0

    for field in sorted_fields:
        gap = field.field_offset - current_offset

        # Skip fields that overlap with previously placed fields (best-effort)
        if gap < 0:
            logger.warning(
                "Skipping overlapping field in struct",
                struct_name=effective_name,
                field_name=field.suggested_field_name,
                field_offset=field.field_offset,
                current_offset=current_offset,
            )
            continue

        if gap > 0:
            padding_name = f"_pad_{padding_counter}[{gap}]"
            fields.append(format_field("char", padding_name))
            padding_counter += 1

        # Substitute struct name in field type based on field's struct_id
        substituted_type = field.field_type
        if field.struct_id is not None:
            referenced_def = definitions.get(field.struct_id)
            referenced_effective = effective_names.get(field.struct_id)
            if (
                referenced_def
                and referenced_effective
                and referenced_def.name != referenced_effective
            ):
                substituted_type = _substitute_field_type(
                    field.field_type,
                    {referenced_def.name: referenced_effective},
                )
                logger.debug(
                    "Substituted struct name in field type",
                    struct_name=effective_name,
                    field_name=field.suggested_field_name,
                    original_type=field.field_type,
                    substituted_type=substituted_type,
                    field_struct_id=field.struct_id,
                )

        try:
            formatted_field = format_field(
                substituted_type, field.suggested_field_name
            )
            field_size = get_field_size(formatted_field)
        except ValueError as e:
            logger.warning(
                "Skipping field that failed to generate",
                struct_name=effective_name,
                field_name=field.suggested_field_name,
                field_type=substituted_type,
                error=str(e),
            )
            continue

        fields.append(formatted_field)
        current_offset = field.field_offset + field_size

    return format_struct(effective_name, fields)
