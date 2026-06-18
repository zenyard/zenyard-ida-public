import hashlib
import json
import os
import subprocess
import sys
import typing as ty
from subprocess import PIPE

import anyio
from anyio.abc import ByteReceiveStream, Process
from anyio.streams.text import TextReceiveStream

from decompai_ida import logger

_RELAY_TOKEN_ENV = "ZENYARD_RELAY_TOKEN"

# Time to allow the sidecar to exit gracefully after closing its stdin before
# terminating it.
_SHUTDOWN_GRACE_SECONDS = 5

# On Windows, prevent the sidecar from allocating a console window (IDA is a
# GUI app, so spawning a console subprocess would flash a window). The flag
# doesn't exist on other platforms.
_CREATE_NO_WINDOW = (
    subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
)


def upstream_id_for_idb(idb_path: str) -> str:
    """Stable per-database routing key for the relay (`ida-<sha256>`)."""
    return "ida-" + hashlib.sha256(idb_path.encode()).hexdigest()


async def get_relay_id(relay_executable: str) -> str:
    """Return this device's stable relay id (`zenyard-relay relay-id`).

    Prints (lazily generating) the per-device id the relay registers under;
    distinct from the per-database `upstream_id`.
    """
    result = await anyio.run_process(
        [relay_executable, "relay-id"],
        creationflags=_CREATE_NO_WINDOW,
    )
    return result.stdout.decode().strip()


def _build_relay_command(
    *,
    relay_executable: str,
    upstream_id: str,
    mcp_url: str,
    binary_name: str,
    binary_id: ty.Optional[str],
    api_url: str,
) -> list[str]:
    command = [
        relay_executable,
        "serve",
        "--id",
        upstream_id,
        "--url",
        mcp_url,
        "--display-name",
        binary_name,
        "--description",
        f"IDA Pro analysis tools for {binary_name}",
        "--tag",
        "decompiler=ida",
    ]
    if binary_id is not None:
        command += ["--tag", f"binary_id={binary_id}"]
    command += [
        "--api-url",
        api_url,
        "--log-format",
        "json",
    ]
    return command


async def run_process(
    *,
    relay_executable: str,
    upstream_id: str,
    mcp_url: str,
    binary_name: str,
    binary_id: ty.Optional[str],
    api_url: str,
    api_key: str,
) -> None:
    """Run the `zenyard-relay` sidecar until it exits.

    Spawns the relay (see `zenyard_relay.binary_path`) pointing at the locally
    hosted MCP server at `mcp_url`, forwards its status/log output, and returns
    when the process exits. On cancellation the sidecar's stdin is closed
    (which it treats as a shutdown signal) and it is terminated if it doesn't
    exit within the grace period.
    """
    command = _build_relay_command(
        relay_executable=relay_executable,
        upstream_id=upstream_id,
        mcp_url=mcp_url,
        binary_name=binary_name,
        binary_id=binary_id,
        api_url=api_url,
    )
    env = {**os.environ, _RELAY_TOKEN_ENV: api_key}

    await logger.ainfo(
        "Starting MCP relay",
        upstream_id=upstream_id,
        mcp_url=mcp_url,
        api_url=api_url,
    )

    process = await anyio.open_process(
        command,
        env=env,
        stdin=PIPE,
        stdout=PIPE,
        stderr=PIPE,
        creationflags=_CREATE_NO_WINDOW,
    )
    try:
        async with anyio.create_task_group() as tg:
            tg.start_soon(_forward_status, process.stdout)
            tg.start_soon(_forward_logs, process.stderr)
            await process.wait()
            await logger.awarning(
                "MCP relay exited", return_code=process.returncode
            )
            # Stop the status/log readers now that the process is gone.
            tg.cancel_scope.cancel()
    finally:
        await _shutdown(process)


async def _forward_status(stdout: ty.Optional[ByteReceiveStream]) -> None:
    if stdout is None:
        return
    async for line in TextReceiveStream(stdout):
        line = line.strip()
        if not line:
            continue
        try:
            status = json.loads(line)
        except json.JSONDecodeError:
            await logger.adebug("MCP relay status", raw=line)
            continue
        await logger.ainfo("MCP relay status", status=status)


async def _forward_logs(stderr: ty.Optional[ByteReceiveStream]) -> None:
    if stderr is None:
        return
    async for line in TextReceiveStream(stderr):
        line = line.strip()
        if line:
            await logger.adebug("MCP relay log", line=line)


async def _shutdown(process: Process) -> None:
    with anyio.CancelScope(shield=True):
        # Closing stdin signals the sidecar to exit gracefully.
        if process.stdin is not None:
            await process.stdin.aclose()

        with anyio.move_on_after(_SHUTDOWN_GRACE_SECONDS):
            await process.wait()

        if process.returncode is None:
            await logger.awarning("MCP relay did not exit in time; terminating")
            process.terminate()
            await process.wait()
