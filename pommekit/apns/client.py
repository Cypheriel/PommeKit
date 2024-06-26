#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel

"""Module containing the high-level APNs client based on the APNs event listener."""

from __future__ import annotations

import asyncio
from asyncio import Event, IncompleteReadError
from logging import getLogger
from typing import TYPE_CHECKING, Self

from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA1

from .._util.event_listener import EventType
from ..apns.listener import APNsListener
from ..apns.protocol.commands import (
    ClientBoundPushNotificationCommand,
    ConnectCommand,
    ConnectResponseCommand,
    FilterTopicsCommand,
    KeepAliveCommand,
)
from ..apns.protocol.transformers import TOPIC_TRANSFORMER, Interface, Nonce, Status, UnknownFlag
from ..apns.streams import APNsClientStream

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    from cryptography.x509 import Certificate

logger = getLogger(__name__)


class APNsClient(APNsListener):
    """High-level APNs client based on the APNs event listener."""

    def __init__(
        self: Self,
        push_token: str | None = None,
        push_key: RSAPrivateKey | None = None,
        push_cert: Certificate | None = None,
        flags: UnknownFlag = UnknownFlag.IS_ROOT,
        interface: Interface = Interface.WIFI,
        carrier: str = "WiFi",
        os_version: str = "10.6.4",
        os_build: str = "10.6.4",
        hardware_version: str = "windows1,1",
        nonce: Nonce = None,
        courier_address: str | None = None,
        courier_port: int = 5223,
    ) -> None:
        """
        Initialize the APNs client.

        :param push_token: The optional push token returned by a prior APNs connection
        :param push_key: The private key used to sign the CSR sent to Albert
        :param push_cert: The push certificate returned by Albert
        :param flags: Device flags — most flags are unknown and undocumented for the time being
        :param interface: The connection interface — Wi-Fi or cellular
        :param carrier: The carrier name or "Wi-Fi" if using Wi-Fi
        :param os_version: The OS version
        :param os_build: The OS build version specifier
        :param hardware_version: The hardware version E.g. "iPhone1,1"
        :param nonce: The nonce used in creation of the signature
        :param courier_address: The address of the APNs courier
        :param courier_port: The courier port
        """
        super().__init__()

        if courier_address is None:
            courier_address = APNsClientStream.fetch_random_courier_address()

        self.courier_address = courier_address
        self.courier_port = courier_port

        self.push_key = push_key
        self.push_cert = push_cert
        self.push_token = push_token

        self.flags = flags
        self.interface = interface
        self.carrier = carrier
        self.os_version = os_version
        self.os_build = os_build
        self.hardware_version = hardware_version
        self.nonce = nonce or Nonce()

        self.signature: bytes | None = None
        self.on_connected_event: Event = Event()

        self._apns_stream: APNsClientStream | None = None

        self._register_default_listeners()

    def _register_default_listeners(self: Self) -> None:
        @self._register_command_listener(ConnectResponseCommand)
        async def _on_connect_response(command: ConnectResponseCommand) -> None:
            if command.status is Status.ERROR:
                logger.error("Received ConnectResponseCommand (0x08) with status ERROR (0x02)!")
                await self.close()
                return

            if command.push_token is not None:
                self.push_token = command.push_token

            self.on_connected_event.set()

            # NOTE: This event should be triggered *after* internal post-connection processing.
            await self._trigger_event(EventType.CONNECT, EventType.CONNECT.name)

        @self._register_command_listener(ClientBoundPushNotificationCommand)
        async def _on_push_notification(command: ClientBoundPushNotificationCommand) -> None:
            topic = TOPIC_TRANSFORMER.serialize(command.topic)

            await self._trigger_event(EventType.TOPIC, topic, self, command)

    async def _connect(self: Self) -> None:
        self._apns_stream = APNsClientStream(self.courier_address, self.courier_port)
        await self._apns_stream.connect()

        connect_command = ConnectCommand(
            push_token=self.push_token,
            state=b"\x01",
            flags=self.flags,
            interface=self.interface,
            carrier=self.carrier,
            os_version=self.os_version,
            os_build=self.os_build,
            hardware_version=self.hardware_version,
            certificate=self.push_cert,
            nonce=self.nonce,
            signature=self.signature,
            protocol_version__=2,
            redirect_count=0,
        )

        logger.debug(f"Sending connect command: {connect_command}")
        logger.debug(f"{connect_command.bytes_debug_repr()}")

        await self._apns_stream.send(connect_command)

    async def filter_topics(self: Self) -> None:
        """Send a FilterTopicsCommand to the APNs courier to filter push notifications to ``self.enabled_topics``."""
        await self._apns_stream.send(
            FilterTopicsCommand(push_token=self.push_token, enabled_topics=self.enabled_topics),
        )

    async def run(self: Self) -> None:
        """Start the APNs client, connect to the courier, filter topics, and dispatch incoming packets to events."""
        if self.push_key is None:
            logger.warning("No push key was provided.")

        if self.push_cert is None:
            logger.warning("No push certificate was provided.")

        if self.push_key is not None and self.push_cert is not None:
            self.signature = b"\x01\x01" + self.push_key.sign(bytes(self.nonce), PKCS1v15(), SHA1())  # noqa: S303

        await self._connect()

        task = asyncio.create_task(self.on_connected_event.wait())
        task.add_done_callback(lambda _: asyncio.create_task(self.filter_topics()))

        while self._apns_stream is not None:
            try:
                command = await self._apns_stream.read()

            except IncompleteReadError:
                await self._apns_stream.send(KeepAliveCommand())
                return

            _results = await self._trigger_event(EventType.COMMAND, command.__class__, command)

    async def close(self: Self) -> None:
        """Close the APNs stream's connection to the APNs courier."""
        if self._apns_stream is not None:
            await self._apns_stream.close()
            self._apns_stream = None
