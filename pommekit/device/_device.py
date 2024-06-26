#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel
"""Module containing the Device class, which represents an emulated Apple device."""

from __future__ import annotations

import json
import logging
import plistlib
from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, StrEnum
from hashlib import sha256
from logging import getLogger
from pathlib import Path
from typing import TYPE_CHECKING, Self
from urllib.parse import urlparse
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from httpx import AsyncClient
from websockets import WebSocketClientProtocol, connect

from .._util.crypto import randbytes
from .._util.url import replace_url
from ..albert.activation import request_push_certificate
from ..apns.client import APNsClient
from ..ids.user import IDSUser

if TYPE_CHECKING:
    from collections.abc import Callable
    from os import PathLike

LOOKUP_URL = "https://gsa.apple.com/grandslam/GsService2/lookup"

logger = getLogger()


class OperatingSystem(StrEnum):
    """Enum containing the operating systems supported by Apple."""

    IOS = "iOS"
    MACOS = "macOS"
    WATCHOS = "watchOS"
    TVOS = "tvOS"
    WINDOWS = "Windows"

    @classmethod
    def _missing_(cls: type[Self], value: str) -> Self:
        for member in cls:
            if value.lower() == member.value.lower():
                return member
        return None


class AnisetteV3Provider(Enum):
    """Enum containing the URLs for the Anisette V3 providers."""

    SIDESTORE = "https://ani.sidestore.io/"


@dataclass
class Device:
    """Class whose objects represent an emulated Apple device."""

    name: str
    operating_system: OperatingSystem
    os_version: str
    os_build: str
    hardware_version: str
    hardware_serial: str
    save_path: PathLike | None = None
    """The folder to save the device's info folder to. If not provided, the device info will not be saved."""

    identifier: str | None = None
    user_agent: str | None = None
    client_info: str | None = None
    adi_pb: str | None = None
    machine_id: str | None = None
    one_time_password: str | None = None
    routing_info: str | None = None

    apns_client: APNsClient | None = None
    ids_users: list[IDSUser] | None = field(default_factory=list)

    provider: AnisetteV3Provider = AnisetteV3Provider.SIDESTORE

    @property
    def anisette_headers(self: Self) -> dict[str, str]:
        """The headers used in Anisette v3-privileged requests."""
        return {header: value for header, value in self._get_header_values().items() if value is not None}

    @property
    def requires_provisioning(self: Self) -> bool:
        """Whether the device requires provisioning."""
        return len(self._get_header_values()) != len(self.anisette_headers)

    @property
    def requires_push_credentials(self: Self) -> bool:
        """Whether the device requires push credentials."""
        return self.apns_client.push_key is None or self.apns_client.push_cert is None

    def __post_init__(self: Self) -> None:
        """Post-initialize the device object."""
        if self.identifier is None:
            self.identifier = b64encode(randbytes(16)).decode()

        if self.save_path is not None:
            self._save_dir = Path(self.save_path)
            logger.debug(f"Loading device info from {self._save_dir}")

        if isinstance(self._save_dir, Path):
            if self._save_dir.name != self.hardware_serial:
                self._save_dir /= self.hardware_serial

            self._users_dir = self._save_dir / "Users"
            self._users_dir.mkdir(parents=True, exist_ok=True)

            self.apns_client = APNsClient(
                os_version=self.os_version,
                os_build=self.os_build,
                hardware_version=self.hardware_version,
            )

        for user_path in self._users_dir.iterdir():
            if user_path.is_dir():
                user = IDSUser(
                    user_path.name,
                    lambda: self.anisette_headers,
                    lambda: self.apns_client.push_token,
                    lambda: self.apns_client.push_key,
                    lambda: self.apns_client.push_cert,
                )
                user.read_credentials(user_path)

                self.ids_users.append(user)

        if isinstance(self.provider, str):
            self.provider_url = urlparse(self.provider)
        else:
            self.provider_url = urlparse(self.provider.value)

        self.client: AsyncClient = AsyncClient(
            verify=False,  # noqa: S501
        )
        self.start_provisioning_url: str | None = None
        self.finish_provisioning_url: str | None = None
        self.provisioning_complete: bool = False

        self.client.headers.update(
            {
                "Content-Type": "text/x-xml-plist",
                "Accept": "*/*",
            },
        )

    async def _fetch_machine_headers(self: Self) -> None:
        """Fetch the machine headers from the Anisette provider."""
        response = await self.client.post(
            replace_url(self.provider_url, path="v3/get_headers"),
            json={
                "identifier": self.identifier,
                "adi_pb": self.adi_pb,
            },
            headers={"Content-Type": "application/json"} | self.anisette_headers,
        )

        response_data = response.json()
        logger.debug(f"Received anisette headers response: {response_data}")

        self.machine_id = response_data["X-Apple-I-MD-M"]
        self.one_time_password = response_data["X-Apple-I-MD"]
        self.routing_info = response_data["X-Apple-I-MD-RINFO"]

    async def _fetch_provisioning_urls(self: Self) -> None:
        """Fetch the provisioning URLs from Apple."""
        response = await self.client.get(LOOKUP_URL, headers=self.anisette_headers)
        response_data = plistlib.loads(response.content)
        logger.debug(f"Received fetch provisioning URLs response: {response_data}")

        urls = response_data["urls"]
        self.start_provisioning_url = urls["midStartProvisioning"]
        self.finish_provisioning_url = urls["midFinishProvisioning"]

    async def _fetch_client_info(self: Self) -> None:
        """Fetch the client info from the Anisette provider."""
        response = await self.client.get(
            replace_url(self.provider_url, path="v3/client_info"),
            headers=self.anisette_headers,
        )
        response_data = response.json()
        logger.debug(f"Received fetch client info response: {response_data}")
        self.user_agent = response_data["user_agent"]
        self.client_info = response_data["client_info"]

    async def _process_response(self: Self, ws: WebSocketClientProtocol, response: dict) -> None:
        """Process the response from the provisioning provider."""
        match response["result"]:
            case "GiveIdentifier":
                await ws.send(json.dumps({"identifier": self.identifier}))

            case "GiveStartProvisioningData":
                logger.debug(f"{self.anisette_headers = }")
                response = await self.client.post(
                    self.start_provisioning_url,
                    content=plistlib.dumps({"Header": {}, "Request": {}}),
                    headers=self.anisette_headers,
                )
                response_data = plistlib.loads(response.content)["Response"]

                logger.debug(f"Received start provisioning data: {response_data}")

                await ws.send(json.dumps({"spim": response_data["spim"]}))

            case "GiveEndProvisioningData":
                response = await self.client.post(
                    self.finish_provisioning_url,
                    content=plistlib.dumps({"Header": {}, "Request": {"cpim": response["cpim"]}}),
                    headers=self.anisette_headers,
                )
                response_data = plistlib.loads(response.content)["Response"]

                logger.debug(f"Received end provisioning data: {response_data}")

                await ws.send(json.dumps({"ptm": response_data["ptm"], "tk": response_data["tk"]}))

            case "ProvisioningSuccess":
                self.adi_pb = response["adi_pb"]
                self.provisioning_complete = True
                await self._fetch_machine_headers()
                logger.info("Provisioning complete!")

    def _get_header_values(self: Self) -> dict[str, str]:
        """Get the header values for the Anisette headers."""
        decoded_uuid = b64decode(self.identifier)
        client_time = datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat()
        return {
            "User-Agent": self.user_agent,
            "X-Apple-I-MD-M": self.machine_id,
            "X-Apple-I-MD": self.one_time_password,
            "X-Apple-I-MD-RINFO": self.routing_info,
            "X-Apple-I-MD-LU": sha256(decoded_uuid).hexdigest().upper(),
            "X-Apple-I-SRL-NO": self.hardware_serial,
            "X-Apple-I-Client-Time": client_time.replace("+00:00", "") + "Z",
            "X-Apple-I-TimeZone": "UTC",
            "X-Apple-Locale": "en_US",
            "X-Mme-Client-Info": self.client_info,
            "X-Mme-Device-Id": str(UUID(bytes=decoded_uuid)).upper(),
        }

    async def start_provisioning(self: Self) -> None:
        """Start the provisioning process."""
        await self._fetch_client_info()
        logger.debug(f"{self.client.headers = }")
        await self._fetch_provisioning_urls()

        provider_url = replace_url(self.provider_url, path="v3/provisioning_session", scheme="wss")

        logger.debug(f"Starting provisioning via provider {provider_url}")

        async with connect(provider_url) as ws:
            while self.provisioning_complete is False:
                response = await ws.recv()
                result = json.loads(response)
                logger.debug(f"Received response: {result}")
                await self._process_response(ws, result)

    async def get_push_credentials(self: Self) -> None:
        """Provision the APNs client by requesting a push certificate."""
        if not self.requires_push_credentials:
            return

        self.apns_client.push_key, self.apns_client.push_cert = await request_push_certificate(
            activation_info_content={
                "ActivationRandomness": str(uuid4()).upper(),
                "ActivationState": "Unactivated",
                "DeviceClass": (
                    "MacOS" if self.operating_system is OperatingSystem.MACOS else self.operating_system.value
                ),
                "ProductType": self.hardware_version,
                "ProductVersion": self.os_version,
                "BuildVersion": self.os_build,
                "SerialNumber": self.hardware_serial,
                "UniqueDeviceID": str(UUID(bytes=b64decode(self.identifier))).upper(),
            },
        )

    def get_user(self: Self, username: str) -> IDSUser | None:
        """Get a user by their Apple ID."""
        for user in self.ids_users:
            if user.apple_id == username:
                return user
        return None

    async def add_user(
        self: Self,
        username: str,
        password_provider: Callable[[], str],
        validation_data_provider: Callable[[], str],
        two_factor_code_provider: Callable[[], str],
    ) -> IDSUser | None:
        """
        Add a user to the device.

        :param username: The Apple ID of the user.
        :param password_provider: A callable that returns the user's password.
        :param validation_data_provider: A callable that returns the user's validation data.
        :param two_factor_code_provider: A callable that returns the user's two-factor code.
        """
        user = IDSUser(
            username,
            lambda: self.anisette_headers,
            lambda: self.apns_client.push_token,
            lambda: self.apns_client.push_key,
            lambda: self.apns_client.push_cert,
        )

        if any(user.apple_id == u.apple_id and u.is_fully_authenticated for u in self.ids_users):
            msg = f"User {username} already exists on this device."
            raise ValueError(msg)

        self.ids_users.append(user)

        await user.start_authentication(password_provider())

        if user.requires_2fa and two_factor_code_provider is not None:
            await user.verify_2fa_code(two_factor_code_provider())
            if user.requires_2fa:
                logger.info("User still requires 2FA code.")
                return None

        elif user.requires_2fa:
            logger.info("User requires 2FA code.")
            return None

        user.log(logging.INFO, "Successfully authenticated user. Adding to device...")
        await user.authenticate_device()
        await user.register_device(
            self.name,
            validation_data_provider(),
            self.operating_system,
            self.hardware_version,
            self.os_version,
            self.os_build,
        )
        user.write_credentials(self._users_dir)

        return user

    @classmethod
    async def remove_user(cls: type[Self], *_args: ..., **_kwargs: ...) -> None:
        """Remove a user from the device, deregister the device from the user, and revoke their credentials."""
        msg = "User removal is not yet implemented."
        raise NotImplementedError(msg)

    async def refresh_user_handles(self: Self) -> None:
        """Refresh the user's handles, verifying their authentication status."""
        for user in self.ids_users:
            await user.fetch_handles()

    def save(self: Self) -> None:
        """Save the device's info, APNs credentials, and users to the save directory."""
        if not isinstance(self._save_dir, Path):
            return

        self._save_dir.mkdir(parents=True, exist_ok=True)

        (self._save_dir / "device_info.json").write_text(
            json.dumps(
                {
                    "name": self.name,
                    "operating_system": self.operating_system.value,
                    "os_version": self.os_version,
                    "os_build": self.os_build,
                    "hardware_version": self.hardware_version,
                    "hardware_serial": self.hardware_serial,
                    "identifier": self.identifier,
                    "user_agent": self.user_agent,
                    "client_info": self.client_info,
                    "adi_pb": self.adi_pb,
                    "machine_id": self.machine_id,
                    "one_time_password": self.one_time_password,
                    "routing_info": self.routing_info,
                },
                indent=4,
            ),
        )

        for user in self.ids_users:
            user.write_credentials(self._users_dir)

        if (push_key := self.apns_client.push_key) is not None:
            (self._save_dir / "push.key").write_bytes(
                push_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()),
            )

        if (push_cert := self.apns_client.push_cert) is not None:
            (self._save_dir / "push.crt").write_bytes(push_cert.public_bytes(Encoding.PEM))

        if (push_token := self.apns_client.push_token) is not None:
            (self._save_dir / "push_token.txt").write_text(push_token)

    @classmethod
    def load(cls: type[Self], path: PathLike) -> Self:
        """Load a device from the specified directory."""
        path = Path(path) if not isinstance(path, Path) else path
        data = json.loads((path / "device_info.json").read_text())

        instance = cls(
            name=data.get("name"),
            operating_system=OperatingSystem(data.get("operating_system")),
            os_version=data.get("os_version"),
            os_build=data.get("os_build"),
            hardware_version=data.get("hardware_version"),
            hardware_serial=data.get("hardware_serial"),
            user_agent=data.get("user_agent"),
            client_info=data.get("client_info"),
            identifier=data.get("identifier"),
            adi_pb=data.get("adi_pb"),
            machine_id=data.get("machine_id"),
            one_time_password=data.get("one_time_password"),
            routing_info=data.get("routing_info"),
            save_path=path,
        )

        if (push_key_path := path / "push.key").is_file():
            instance.apns_client.push_key = load_pem_private_key(push_key_path.read_bytes(), password=None)

        if (push_cert_path := path / "push.crt").is_file():
            instance.apns_client.push_cert = load_pem_x509_certificate(push_cert_path.read_bytes())

        if (push_token_path := path / "push_token.txt").is_file():
            instance.apns_client.push_token = push_token_path.read_text()

        return instance
