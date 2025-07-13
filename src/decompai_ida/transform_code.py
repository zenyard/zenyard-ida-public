"""
Utilities for working with model objects.
"""

import typing as ty

from decompai_client import Function, Range, RangeDetail


def transform_code(
    func: Function,
    callback: ty.Callable[[str, RangeDetail], str],
) -> Function:
    """
    Transform ranges with details (address, lvars) using given callback.

    Callback receives original text and details of each range, and returns
    new text to replace original.
    """

    transformed_ranges = list[Range]()
    transformed_parts = list[str]()
    current_start = 0

    for part, range in _code_slices(func):
        if range is not None:
            transformed_part = callback(part, range.detail)
            transformed_parts.append(transformed_part)
            transformed_ranges.append(
                Range(
                    detail=range.detail,
                    start=current_start,
                    length=len(transformed_part),
                )
            )
        else:
            transformed_parts.append(part)
        current_start += len(transformed_parts[-1])

    return Function(
        address=func.address,
        name=func.name,
        has_known_name=func.has_known_name,
        type=func.type,
        code="".join(transformed_parts),
        ranges=transformed_ranges,
        calls=func.calls,
        inference_seq_number=func.inference_seq_number,
    )


def _code_slices(
    func: Function,
) -> ty.Iterator[tuple[str, ty.Optional[Range]]]:
    sorted_ranges = sorted(func.ranges or (), key=lambda r: r.start)
    last_end = 0

    for r in sorted_ranges:
        # Yield any uncovered slice before this range
        if r.start > last_end:
            yield func.code[last_end : r.start], None

        # Current range
        yield func.code[r.start : r.start + r.length], r
        last_end = r.start + r.length

    # Yield any remaining slice after the last range
    if last_end < len(func.code):
        yield func.code[last_end:], None
