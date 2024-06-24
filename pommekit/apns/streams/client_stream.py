#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel
"""APNsClientStream class definition."""

from __future__ import annotations

import asyncio
import logging
import socket
from asyncio import StreamReader, StreamWriter
from logging import getLogger
from typing import TYPE_CHECKING, Final, Self

from ..._util.crypto import randint
from ..streams._apns_stream import ConnectionType, _APNsStream

if TYPE_CHECKING:
    from types import TracebackType

    from ..protocol.packet import APNsCommand

COURIER_HOSTNAME_TEMPLATE: Final = "{0}-courier.push.apple.com"

logger = getLogger(__name__)


class APNsClientStream(_APNsStream):
    """Stream class for client connections to the APNs courier."""

    def __init__(self: Self, host: str | None = None, port: int = 5223) -> None:
        """Initialize a new APNs client stream."""
        if host is not None:
            addr_info = socket.getaddrinfo(host, port)
            host, port, *_ = addr_info[0][4]

        super().__init__(ConnectionType.CLIENT, host, port)

        self._stream_writer: StreamWriter | None = None
        self._stream_reader: StreamReader | None = None
        self._logger = getLogger(f"{__name__}.{self.__class__.__name__}")

    async def __aenter__(self: Self) -> Self:
        """Async context manager enter method."""
        await self.connect()
        return self

    async def __aexit__(
        self: Self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Async context manager exit method."""
        await self.close()

    def log(
        self: Self,
        level: int,
        msg: str,
        *args: str,
        client_address: tuple[str, int] | None = None,
        **kwargs: ...,
    ) -> None:
        """Log a message with the client address if available."""
        addr_repr = f"[{client_address[0]}:{client_address[1]}] " if client_address else ""
        self._logger.log(level, f"Client :: {addr_repr}{msg}", *args, **kwargs, stacklevel=2)

    @staticmethod
    def fetch_random_courier_address() -> str:
        """Generate a random APNs courier address."""
        return COURIER_HOSTNAME_TEMPLATE.format(randint(1, 50))

    async def connect(self: Self) -> None:
        """Connect to the APNs courier and perform the TLS handshake."""
        if self.host is None:
            self.host = self.fetch_random_courier_address()

        self.log(logging.DEBUG, f"Connecting to APNs courier at {self.host}:{self.port}...")

        self._stream_reader, self._stream_writer = await asyncio.open_connection(
            self.host,
            self.port,
            ssl=self._create_ssl_context(ConnectionType.CLIENT),
        )

        self.log(logging.DEBUG, "TLS handshake successful and connection established.")

    async def close(self: Self) -> None:
        """Close the connection to the APNs courier."""
        self.log(logging.DEBUG, "Closing connection to APNs courier...")
        self._stream_writer.close()
        await self._stream_writer.wait_closed()

    async def read(self: Self) -> APNsCommand:
        """Read a command from the stream."""
        result = await super()._read_command(self._stream_reader)
        self.log(logging.DEBUG, f"Received {result.__class__.__name__} (0x{result.command_id:02X}).")
        return result

    async def send(self: Self, command: APNsCommand) -> None:
        """Send a command to the stream."""
        self.log(logging.DEBUG, f"Sending {command.__class__.__name__} (0x{command.command_id:02X}).")
        await super()._send_command(self._stream_writer, command)
