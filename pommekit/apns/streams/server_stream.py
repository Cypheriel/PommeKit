#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel
"""APNsServerStream class definition."""

from __future__ import annotations

import asyncio
import logging
from asyncio import Server, StreamReader, StreamWriter
from logging import getLogger
from typing import TYPE_CHECKING, Awaitable, Callable, Self

from ..streams._apns_stream import ConnectionType, _APNsStream

if TYPE_CHECKING:
    from types import TracebackType

    from ..protocol.packet import APNsCommand


class APNsServerStream(_APNsStream):
    """Stream class for server APNs courier hosts."""

    def __init__(self: Self, host: str = "localhost", port: int = 5223) -> None:
        """Initialize a new APNs server stream."""
        super().__init__(ConnectionType.SERVER, host, port)

        self._server: Server | None = None
        self._handle_client: Callable[[APNsServerStream, StreamReader, StreamWriter], Awaitable[None]] | None = None
        self._logger = getLogger(f"{__name__}.{self.__class__.__name__}")

    async def __aenter__(self: Self) -> Self:
        """Async context manager enter method."""
        await self.start()
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
        """Log a message with the server's logger."""
        addr_repr = f"[{client_address[0]}:{client_address[1]}] " if client_address else ""
        self._logger.log(level, f"Server :: {addr_repr}{msg}", *args, **kwargs, stacklevel=2)

    async def start(self: Self, server: Server | None = None) -> None:
        """Start the server."""
        self._server = server or await asyncio.start_server(
            self._wrapped_callback,
            self.host,
            self.port,
            ssl=self._create_ssl_context(ConnectionType.SERVER),
        )

        self.log(logging.DEBUG, f"Listening on {self.host}:{self.port} for APNs connections!")

    async def close(self: Self) -> None:
        """Close the server."""
        self._server.close()
        await self._server.wait_closed()

    async def wait_closed(self: Self) -> None:
        """Wait for the server to close."""
        await self._server.wait_closed()

    def set_callback(
        self: Self,
        callback: Callable[[APNsServerStream, StreamReader, StreamWriter], Awaitable[None]],
    ) -> None:
        """Set the callback to handle client connections."""
        self._handle_client = callback

    async def _wrapped_callback(self: Self, stream_reader: StreamReader, stream_writer: StreamWriter) -> None:
        """Wrap the callback to handle logging and other tasks."""
        client_host, client_port, *_ = stream_writer.get_extra_info("peername")
        self.log(logging.DEBUG, "Received client connection.", client_address=(client_host, client_port))

        await self._handle_client(self, stream_reader, stream_writer)

        self.log(logging.DEBUG, "Finished handling client connection.", client_address=(client_host, client_port))

    async def send(self: Self, stream_writer: StreamWriter, command: APNsCommand) -> None:
        """Send a command to the stream."""
        addr_info = stream_writer.get_extra_info("peername")

        self.log(
            logging.DEBUG,
            f"Sending {command.__class__.__name__} (0x{command.command_id:02X}).",
            client_address=addr_info,
        )
        await self._send_command(stream_writer, command)

    async def read(self: Self, stream_reader: StreamReader) -> APNsCommand:
        """Read a command from the stream."""
        return await self._read_command(stream_reader)
