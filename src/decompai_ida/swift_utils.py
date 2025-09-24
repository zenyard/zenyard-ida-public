import typing as ty

import ida_nalt
from decompai_client.models.swift_function import SwiftFunction
from decompai_ida.model import Model


def find_latest_swift_function_inference_sync(
    model: Model, address: int
) -> ty.Optional[SwiftFunction]:
    """Find the latest SwiftFunction inference for the given address."""
    for inference in model.inferences.read_sync(address):
        if isinstance(inference, SwiftFunction):
            return inference
    return None


def is_swift_binary_sync() -> bool:
    """Check if the current binary is a Swift binary based on ABI name."""
    return ida_nalt.get_abi_name() == "swift"
