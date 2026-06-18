import typing as ty

import anyio

from zenyard_relay import binary_path

from decompai_ida import binary, ida_tasks, logger, relay
from decompai_ida.async_utils import wait_until_cancelled
from decompai_ida.events import AddressModified
from decompai_ida.model import RelayIdentity
from decompai_ida.tasks import Task

if ty.TYPE_CHECKING:
    from decompai_ida.mcp.vendor.zeromcp import McpServer

# Backoff before respawning the relay sidecar after it exits while the server
# is still up, so an immediately-dying sidecar doesn't spin.
_RELAY_RESTART_DELAY_SECONDS = 5


class McpServerTask(Task):
    """Hosts the local MCP server exposing IDA analysis tools.

    The server's HTTP transport runs on its own (non-anyio) threads; tool
    bodies are marshalled onto IDA's main thread by `decompai_ida.mcp.bridge`
    via this task's event loop. The task owns the server lifecycle: it starts
    when a database opens (if enabled in configuration) and stops when the
    task is cancelled on database close or IDA exit.
    """

    async def _run(self) -> None:
        config = self._ctx.plugin_config
        if not config.mcp_enabled:
            await logger.adebug("MCP server disabled in configuration")
            return

        # Building the server imports the vendored package, which touches
        # IDAPython at import time (e.g. compat.py reads the kernel version),
        # so it must run on the main thread.
        server = await ida_tasks.run(self._build_server_sync)

        try:
            server.serve(config.mcp_host, config.mcp_port, background=True)
        except OSError as ex:
            # A fixed port may already be bound. Don't crash-loop via the base
            # task retry; report and stay idle until cancelled.
            await logger.aerror(
                "Failed to start MCP server",
                host=config.mcp_host,
                port=config.mcp_port,
                exc_info=ex,
            )
            await wait_until_cancelled()
            return

        # The server is now serving on its own thread. From here on every exit
        # path -- including cancellation at any `await` below -- must stop it,
        # so all remaining work runs inside the try whose finally calls
        # `server.stop()`. (`serve` cleans up after itself on the OSError path
        # above, so that case must stay outside this try.)
        try:
            # With mcp_port=0 the OS assigns a free port; read back the real one.
            assert server._http_server is not None
            bound_port = server._http_server.server_address[1]

            # The relay connects over the loopback interface even when the
            # server binds a wildcard address.
            connect_host = (
                "127.0.0.1" if config.mcp_host == "0.0.0.0" else config.mcp_host
            )
            url = f"http://{connect_host}:{bound_port}/mcp"

            await logger.ainfo(
                "MCP server listening",
                url=url,
                host=config.mcp_host,
                port=bound_port,
                tool_count=len(server.tools.methods),
            )

            async with anyio.create_task_group() as tg:
                # Tunnel this server to the backend for the server's lifetime;
                # the relay is torn down with the task group on any exit.
                tg.start_soon(self._supervise_relay, url)

                async with self._ctx.ida_events.subscribe(
                    replay_recorded=False
                ) as event_receiver:
                    async for event in event_receiver:
                        # The vendored strings cache can go stale after the
                        # database is mutated; clear it (lazy rebuild on next
                        # use).
                        if isinstance(event, AddressModified):
                            await ida_tasks.run(
                                self._invalidate_strings_cache_sync
                            )
        finally:
            with anyio.CancelScope(shield=True):
                await logger.ainfo("Stopping MCP server")
                # stop() joins the serving thread; must run off that thread,
                # which holds here (we are on the anyio background thread).
                server.stop()

    async def _supervise_relay(self, mcp_url: str) -> None:
        """Keep a `zenyard-relay` sidecar tunneling `mcp_url` to the backend.

        Restarts the sidecar (after a short backoff) if it exits while the
        server is still up. Cancelled together with the server when the
        database closes. The URL is a local value here -- no model state is
        needed to hand it to the relay, since the server owns the relay's
        lifecycle directly.
        """
        config = self._ctx.plugin_config

        try:
            relay_executable = binary_path()
        except FileNotFoundError as ex:
            # Without the sidecar the server is still useful to local clients,
            # so report and leave it serving without a tunnel.
            await logger.aerror(
                "zenyard-relay executable not found; relay not started",
                exc_info=ex,
            )
            return

        idb_path = await ida_tasks.run(binary.get_idb_path_sync)
        binary_name = (await ida_tasks.run(binary.get_binary_path_sync)).name

        # The server is ready and we have the relay executable; publish the
        # ids it will tunnel under so other tasks can surface them.
        upstream_id = relay.upstream_id_for_idb(str(idb_path))
        relay_id = await relay.get_relay_id(str(relay_executable))
        self._ctx.model.runtime_status.relay_identity = RelayIdentity(
            relay_id=relay_id, upstream_id=upstream_id
        )
        self._ctx.model.notify_update()

        while True:
            await relay.run_process(
                relay_executable=str(relay_executable),
                upstream_id=upstream_id,
                mcp_url=mcp_url,
                binary_name=binary_name,
                binary_id=await self._ctx.model.binary_id.get(),
                api_url=str(config.api_url),
                api_key=config.api_key,
            )
            await anyio.sleep(_RELAY_RESTART_DELAY_SECONDS)

    def _build_server_sync(self) -> "McpServer":
        from decompai_ida.mcp import registry

        return registry.build_server()

    def _invalidate_strings_cache_sync(self) -> None:
        from decompai_ida.mcp.vendor import api_core

        api_core.invalidate_strings_cache()
