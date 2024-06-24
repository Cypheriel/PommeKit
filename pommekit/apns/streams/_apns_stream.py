#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel
from __future__ import annotations

import ssl
from enum import Enum, auto
from importlib import resources
from logging import getLogger
from ssl import SSLContext
from tempfile import TemporaryFile
from typing import TYPE_CHECKING, Final, Self

from ..protocol.commands import COMMAND_MAP, Direction

if TYPE_CHECKING:
    from asyncio import StreamReader, StreamWriter
    from importlib.abc import Traversable

    from ..protocol.packet import APNsCommand

_RESOURCE_ROOT = resources.files(__package__)
_SERVER_CERTIFICATE = _RESOURCE_ROOT / "server.crt"
_SERVER_PRIVATE_KEY = _RESOURCE_ROOT / "server.key"

ALPN_PROTOCOL: Final = ("apns-security-v3",)

logger = getLogger(__name__)


class ConnectionType(Enum):
    CLIENT = auto()
    SERVER = auto()


class _APNsStream:
    def __init__(self: Self, connection_type: ConnectionType, host: str | None = None, port: int = 5223) -> None:
        """Initialize a new APNs stream."""
        self.host = host
        self.port = port
        self.connection_type = connection_type

        if self.connection_type not in {ConnectionType.CLIENT, ConnectionType.SERVER}:
            msg = f"Invalid direction for APNs stream: {self.connection_type}"
            raise ValueError(msg)

    @staticmethod
    def _create_ssl_context(
        connection_type: ConnectionType,
        cert_file_path: Traversable | None = None,
        key_file_path: Traversable | None = None,
    ) -> SSLContext:
        """Create an SSL context for the APNs connection."""
        if cert_file_path is None and key_file_path is None:
            cert_file = TemporaryFile()
            cert_file.write(_SERVER_CERTIFICATE.read_bytes())

            key_file = TemporaryFile()
            key_file.write(_SERVER_PRIVATE_KEY.read_bytes())
        elif cert_file_path is not None and key_file_path is not None:
            cert_file = cert_file_path
            key_file = key_file_path
        else:
            msg = "Both certificate and private key paths must be provided."
            raise ValueError(msg)

        match connection_type:
            case ConnectionType.CLIENT:
                ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            case ConnectionType.SERVER:
                ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ssl_context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
                ssl_context.options |= ssl.OP_SINGLE_DH_USE
                ssl_context.options |= ssl.OP_SINGLE_ECDH_USE
            case _:
                msg = f"Invalid connection type: {connection_type}"
                raise ValueError(msg)

        ssl_context.set_alpn_protocols(ALPN_PROTOCOL)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        return ssl_context

    @staticmethod
    async def _read_packet(stream_reader: StreamReader) -> bytes:
        """Read a packet from the stream."""
        command_id = await stream_reader.readexactly(1)
        command_length = await stream_reader.readexactly(4)
        items_data = await stream_reader.readexactly(int.from_bytes(command_length))
        return command_id + command_length + items_data

    async def _read_command(self: Self, stream_reader: StreamReader) -> APNsCommand:
        """Read an `APNsCommand`-deserialized object from the stream."""
        packet = await self._read_packet(stream_reader)

        match self.connection_type:
            case ConnectionType.CLIENT:
                direction = Direction.CLIENT_BOUND
            case ConnectionType.SERVER:
                direction = Direction.SERVER_BOUND
            case _:
                msg = f"Invalid connection type: {self.connection_type}"
                raise ValueError(msg)

        for (command_id, command_direction), command_type in COMMAND_MAP.items():
            if command_id == packet[0] and direction in command_direction:
                return command_type.from_bytes(packet, includes_header=True)

        msg = f"Failed to find command for packet: {packet!r} ({direction})"
        raise ValueError(msg)

    @staticmethod
    async def _send_packet(stream_writer: StreamWriter, packet: bytes) -> None:
        """Send a packet to the stream."""
        stream_writer.write(packet)
        await stream_writer.drain()

    async def _send_command(self: Self, stream_writer: StreamWriter, command: APNsCommand) -> None:
        """Send an `APNsCommand`, bytes-serialized, object to the stream."""
        await self._send_packet(stream_writer, bytes(command))
