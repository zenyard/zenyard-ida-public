from inspect import cleandoc
from pathlib import Path
import typing as ty

import ida_kernwin
from decompai_client.models.swift_rejection_reason import SwiftRejectionReason

from decompai_ida import ida_tasks


async def confirm_analyze_binary() -> bool:
    message = cleandoc("""
        BUTTON YES ~Y~es
        BUTTON CANCEL* ~S~kip
        Run Zenyard?


        Would you like Zenyard to run on this file?
    """)

    result = await ida_tasks.run_ui(ida_kernwin.ask_form, message)
    return result == ida_kernwin.ASKBTN_YES


async def warn_no_permission_for_binary():
    message = cleandoc("""
        Heads up! This IDA database was created and analyzed by
        Zenyard on another system, so no further analysis will run
        here.
    """)

    await ida_tasks.run_ui(ida_kernwin.warning, message)


async def warn_bad_configuration(*, config_path: Path):
    message = cleandoc(f"""
        Bad or missing Zenyard configuration at '{config_path}.'

        Correct the configuration and restart IDA to enable Zenyard.,
    """)

    await ida_tasks.run_ui(ida_kernwin.warning, message)


async def warn_bad_credentials_message():
    message = cleandoc("""
        Bad Zenyard credentials.

        Correct the configuration to enable Zenyard.
    """)

    await ida_tasks.run_ui(ida_kernwin.warning, message)


async def warn_binary_exceeds_max_size(*, max_size_mb: int):
    message = cleandoc(f"""
        The demo version of Zenyard supports binaries up to {max_size_mb}MB (full versions have no limit).
        As this database exceeds the limit, Zenyard has been disabled for this session.
    """)

    await ida_tasks.run_ui(ida_kernwin.warning, message)


def inform_no_swift_source_code_sync(
    reason: ty.Optional[SwiftRejectionReason] = None,
) -> None:
    if reason == SwiftRejectionReason.TOO_SHORT:
        message = (
            "This function was not analyzed as Swift since it's too short."
        )
    elif reason == SwiftRejectionReason.HAS_NON_SWIFT_NAME:
        message = "This function was not analyzed as Swift since it has non-Swift name."
    elif reason == SwiftRejectionReason.COMPILER_GENERATED:
        message = "This function was not analyzed as Swift since it's likely auto-generated."
    elif reason == SwiftRejectionReason.DOESNT_LOOK_LIKE_SWIFT:
        message = "This function was not analyzed as Swift since it's not conclusively Swift."
    else:
        message = "This function doesn't have Swift source code."

    ida_kernwin.info(f"AUTOHIDE NONE\n{message}")


def warn_cant_open_swift_pseudocode_sync():
    ida_kernwin.warning(
        "AUTOHIDE NONE\nCould not open pseudocode for Swift function."
    )
