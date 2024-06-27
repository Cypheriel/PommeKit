#  Copyright (C) 2024  Cypheriel
import json
import plistlib
from base64 import b64encode
from enum import StrEnum
from logging import getLogger
from typing import TYPE_CHECKING, Final, Self
from urllib.parse import urlparse

import websockets
from httpx import AsyncClient, Response
from websockets import ConnectionClosedOK

from ..._util.crypto import randbytes
from ..._util.url import replace_url
from ...device import MachineDataComponent
from ..exceptions import (
    AnisetteProvisioningError,
    ClientInfoFetchError,
    EndProvisioningRequestError,
    ProvisioningURLFetchError,
    StartProvisioningRequestError,
    UnexpectedRemoteResponseError,
)

if TYPE_CHECKING:
    from .._types import (
        ClientInfoResult,
        EndProvisioningResult,
        LookupResult,
        MachineHeadersFetchResult,
        StartProvisioningResult,
    )

LOOKUP_URL: Final = "https://gsa.apple.com/grandslam/GsService2/lookup"

logger = getLogger()


class RemoteAnisetteV3Server(StrEnum):
    """Enum containing the URLs for the Anisette V3 providers."""

    SIDESTORE = "https://ani.sidestore.io/"


class AnisetteV3Provider:
    @property
    def client(self: Self) -> AsyncClient:
        self._client.headers.update(self.machine_data.anisette_headers)
        return self._client

    def __init__(
        self: Self,
        machine_data: MachineDataComponent,
        remote_server: RemoteAnisetteV3Server | str = RemoteAnisetteV3Server.SIDESTORE,
    ) -> None:
        self.machine_data = machine_data
        self.remote_server_address = urlparse(remote_server)

        if self.machine_data.identifier is None:
            self.machine_data.identifier = b64encode(randbytes(16)).decode()

        self._client = AsyncClient(
            verify=False,  # noqa: S501
        )

        self._start_provisioning_url: str | None = None
        self._end_provisioning_url: str | None = None

    async def _fetch_client_info(self: Self) -> None:
        response = await self.client.get(replace_url(self.remote_server_address, path="v3/client_info"))

        if response.is_error:
            msg = f"Failed to fetch client info: {response.text}"
            raise ClientInfoFetchError(msg)

        response_data: ClientInfoResult = response.json()
        logger.debug(f"Received client info response: {response_data}")

        user_agent = response_data["user_agent"]
        client_info = response_data["client_info"]

        self.machine_data.user_agent = user_agent
        self.machine_data.client_info = client_info

    async def _fetch_provisioning_urls(self: Self) -> None:
        response = await self.client.post(LOOKUP_URL)

        if response.is_error:
            msg = f"Failed to fetch provisioning URLs: {response.text}"
            raise ProvisioningURLFetchError(msg)

        response_data: LookupResult = plistlib.loads(response.content)
        logger.debug(f"Received provisioning URLs response: {response_data}")

        urls = response_data["urls"]
        self._start_provisioning_url = urls["midStartProvisioning"]
        self._end_provisioning_url = urls["midFinishProvisioning"]

    async def _fetch_machine_headers(self: Self) -> None:
        response = await self._client.post(
            replace_url(self.remote_server_address, path="v3/get_headers"),
            json={
                "identifier": self.machine_data.identifier,
                "adi_pb": self.machine_data.adi_pb,
            },
        )

        if response.is_error:
            msg = f"Failed to fetch machine headers: {response.text}"
            raise ClientInfoFetchError(msg)

        response_data: MachineHeadersFetchResult = response.json()
        logger.debug(f"Received machine headers response: {response_data}")

        self.machine_data.machine_id = response_data["X-Apple-I-MD-M"]
        self.machine_data.one_time_password = response_data["X-Apple-I-MD"]
        self.machine_data.routing_info = response_data["X-Apple-I-MD-RINFO"]

    async def _process_response(self: Self, ws_response: dict) -> dict | None:
        match ws_response["result"]:
            case "GiveIdentifier":
                return {"identifier": self.machine_data.identifier}

            case "GiveStartProvisioningData":
                response: Response = await self.client.post(
                    self._start_provisioning_url,
                    content=plistlib.dumps({"Header": {}, "Request": {}}),
                )

                if response.is_error:
                    raise StartProvisioningRequestError(response.status_code, response.content)

                response_data: StartProvisioningResult = plistlib.loads(response.content)["Response"]
                logger.debug(f"Received start provisioning data: {response_data}")

                return {"spim": response_data["spim"]}

            case "GiveEndProvisioningData":
                response: Response = await self.client.post(
                    self._end_provisioning_url,
                    content=plistlib.dumps({"Header": {}, "Request": {"cpim": ws_response["cpim"]}}),
                )

                if response.is_error:
                    raise EndProvisioningRequestError(response.status_code, response.content)

                response_data: EndProvisioningResult = plistlib.loads(response.content)["Response"]
                logger.debug(f"Received end provisioning data: {response_data}")

                return {"ptm": response_data["ptm"], "tk": response_data["tk"]}

            case "ProvisioningSuccess":
                adi_pb = ws_response["adi_pb"]
                self.machine_data.adi_pb = adi_pb
                await self._fetch_machine_headers()
                logger.info("Provisioning complete!")
                return None

            case _:
                raise UnexpectedRemoteResponseError(ws_response)

    async def provision(self: Self) -> None:
        await self._fetch_client_info()
        await self._fetch_provisioning_urls()

        provisioning_session_url = replace_url(self.remote_server_address, path="v3/provisioning_session", scheme="wss")

        async with websockets.connect(provisioning_session_url) as ws:
            try:
                while self.machine_data.requires_provisioning:
                    response_data = await self._process_response(json.loads(await ws.recv()))
                    await ws.send(json.dumps(response_data))

            except ConnectionClosedOK:
                logger.info("Provisioning session closed.")

            if self.machine_data.requires_provisioning:
                msg = "Provisioning requirements unsatisfied despite session closure."
                raise AnisetteProvisioningError(msg)
