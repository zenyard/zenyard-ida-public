import socket
import webbrowser
from functools import cached_property

from decompai_client import ApiClient, WebApi
from decompai_client.models.create_link_request import CreateLinkRequest
from decompai_ida.ida_tasks import AsyncCallback
from decompai_ida.model import Model


class WebUI:
    """
    Allows opening specific parts of the Web UI.

    Note: all methods can be called from either background or main thread.
    """

    def __init__(self, *, api_client: ApiClient, install_id: str, model: Model):
        self._install_id = install_id
        self._model = model
        self._web_api = WebApi(api_client)
        self._open_client = AsyncCallback(self._open_client_async)

    @cached_property
    def _token_description(self) -> str:
        return f"Login from IDA at {socket.gethostname()}"

    def open_new_agent(self) -> None:
        relay_identity = self._model.runtime_status.relay_identity
        if relay_identity is None:
            raise RuntimeError(
                "Cannot open agent before relay identity is available"
            )
        self._open_client(
            f"chats?upstreams={relay_identity.relay_id}"
            f":{relay_identity.upstream_id}"
        )

    async def _open_client_async(self, path: str) -> None:
        response = await self._web_api.create_link(
            CreateLinkRequest(
                redirect_to=path,
                token_id=self._install_id,
                description=self._token_description,
            )
        )
        webbrowser.open(response.url, new=2, autoraise=True)
