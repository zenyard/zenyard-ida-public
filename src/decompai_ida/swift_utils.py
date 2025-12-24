from collections import defaultdict
from dataclasses import dataclass
import typing as ty

import ida_lines
import ida_nalt
from decompai_client import SwiftSpeculation
from decompai_client import TranslationProfile
from decompai_client.models.swift_function import SwiftFunction
from decompai_ida.model import Model


@dataclass(frozen=True)
class NumberedSpeculation:
    number: int
    speculation: SwiftSpeculation


def find_latest_swift_function_inference_per_profile_sync(
    model: Model, address: int
) -> ty.Mapping[TranslationProfile, SwiftFunction]:
    output: dict[TranslationProfile, SwiftFunction] = {}
    for inference in model.inferences.read_sync(address):
        if not isinstance(inference, SwiftFunction):
            continue
        profile = inference.profile or TranslationProfile.BALANCED
        if profile not in output:
            output[profile] = inference
    return output


def find_latest_swift_function_inference_sync(
    model: Model, address: int
) -> ty.Optional[SwiftFunction]:
    """Find the latest SwiftFunction inference for the given address."""
    inferences_by_profile = (
        find_latest_swift_function_inference_per_profile_sync(
            model=model,
            address=address,
        )
    )
    for profile in (
        TranslationProfile.BALANCED,
        TranslationProfile.RISKY,
        TranslationProfile.CONSERVATIVE,
    ):
        swift_function = inferences_by_profile.get(profile)
        if swift_function is not None:
            return swift_function
    return None


def is_swift_binary_sync() -> bool:
    """Check if the current binary is a Swift binary based on ABI name."""
    return ida_nalt.get_abi_name() == "swift"


NumberedSpeculationsPerLine: ty.TypeAlias = ty.Mapping[
    int, ty.Sequence[NumberedSpeculation]
]


def build_speculations_per_line(
    swift_function: SwiftFunction,
) -> NumberedSpeculationsPerLine:
    output = defaultdict[int, list[NumberedSpeculation]](list)
    for speculation_number, speculation in enumerate(
        swift_function.speculations or (),
        start=1,
    ):
        numbered_speculation = NumberedSpeculation(
            number=speculation_number,
            speculation=speculation,
        )
        for line_number in _iter_run_starts(speculation.source_line_numbers):
            output[line_number].append(numbered_speculation)

    return {
        line_number: tuple(
            sorted(
                line_speculations,
                key=lambda numbered: (
                    numbered.speculation.is_trivial,
                    numbered.number,
                ),
            )
        )
        for line_number, line_speculations in output.items()
    }


def format_speculation_marker(numbered_speculation: NumberedSpeculation) -> str:
    color = (
        ida_lines.SCOLOR_AUTOCMT
        if numbered_speculation.speculation.is_trivial
        else ida_lines.SCOLOR_VOIDOP
    )
    return ida_lines.COLSTR(
        f"[{numbered_speculation.number}]",
        color,
    )


def speculation_marker_width(numbered_speculation: NumberedSpeculation) -> int:
    return len(str(numbered_speculation.number)) + 3


def _iter_run_starts(line_numbers: ty.Iterable[int]) -> ty.Iterator[int]:
    sorted_unique_numbers = sorted(set(line_numbers))
    previous_number: ty.Optional[int] = None
    for line_number in sorted_unique_numbers:
        if previous_number is None or line_number != previous_number + 1:
            yield line_number
        previous_number = line_number
