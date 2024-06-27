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
    from ..device import (
        APNsCredentialsComponent,
        DeviceInfoComponent,
        ProvidesDeviceInfo,
        ProvidesPushKeypair,
    )

logger = getLogger(__name__)


class APNsClient(APNsListener):
    """High-level APNs client based on the APNs event listener."""

    def __init__(
        self: Self,
        push_credential_provider: APNsCredentialsComponent | ProvidesPushKeypair,
        device_info_provider: DeviceInfoComponent | ProvidesDeviceInfo,
        courier_address: tuple[str | None, int] = (None, 5223),
    ) -> None:
        """
        Initialize the APNs client.

        :param push_credential_provider: Object that provides the `push_key` and `push_cert` properties
        :param courier_address: The address of the APNs courier
        """
        super().__init__()

        if courier_address[0] is None:
            courier_address = (APNsClientStream.fetch_random_courier_address(), courier_address[1])

        self.courier_address = courier_address

        self._push_credential_provider = push_credential_provider
        self._device_info_provider = device_info_provider

        self.flags = UnknownFlag.IS_ROOT
        self.interface = Interface.WIFI
        self.carrier = "WiFi"

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
                self._push_credential_provider.push_token = command.push_token

            self.on_connected_event.set()

            # NOTE: This event should be triggered *after* internal post-connection processing.
            await self._trigger_event(EventType.CONNECT, EventType.CONNECT.name)

        @self._register_command_listener(ClientBoundPushNotificationCommand)
        async def _on_push_notification(command: ClientBoundPushNotificationCommand) -> None:
            topic = TOPIC_TRANSFORMER.serialize(command.topic)

            await self._trigger_event(EventType.TOPIC, topic, self, command)

    async def _connect(self: Self) -> None:
        push_key = self._push_credential_provider.push_key
        push_cert = self._push_credential_provider.push_cert

        if not push_key or not push_cert:
            msg = "Valid push credentials were not provided."
            raise ValueError(msg)

        self._apns_stream = APNsClientStream(*self.courier_address)
        await self._apns_stream.connect()

        connect_command = ConnectCommand(
            push_token=self._push_credential_provider.push_token,
            state=b"\x01",
            flags=self.flags,
            interface=self.interface,
            carrier=self.carrier,
            os_version=self._device_info_provider.operating_system_version,
            os_build=self._device_info_provider.operating_system_build,
            hardware_version=self._device_info_provider.model_number,
            certificate=push_cert,
            nonce=(nonce := Nonce()),
            signature=b"\x01\x01" + push_key.sign(bytes(nonce), PKCS1v15(), SHA1()),  # noqa: S303,
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
        await self._connect()

        task = asyncio.create_task(self.on_connected_event.wait())
        task.add_done_callback(lambda _: asyncio.create_task(self.filter_topics()))

        while self._apns_stream is not None:
            try:
                command = await self._apns_stream.read()

            except IncompleteReadError:
                await self._apns_stream.send(
                    KeepAliveCommand(
                        connection_method="WiFi",
                        os_version=self._device_info_provider.operating_system_version,
                        os_build=self._device_info_provider.operating_system_build,
                        hardware_version=self._device_info_provider.model_number,
                    ),
                )
                return

            _results = await self._trigger_event(EventType.COMMAND, command.__class__, command)

    async def close(self: Self) -> None:
        """Close the APNs stream's connection to the APNs courier."""
        if self._apns_stream is not None:
            await self._apns_stream.close()
            self._apns_stream = None
