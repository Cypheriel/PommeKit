#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel
"""Submodule containing known APNs commands and their respective packet fields as well as a command registry."""

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Flag, auto
from logging import getLogger
from typing import Annotated, Collection, Final, Literal, TypeAlias, TypeVar

from cryptography.x509 import Certificate

from ..protocol.packet import APNsCommand, Item
from ..protocol.transformers import (
    CAPABILITIES_TRANSFORMER,
    DER_CERTIFICATE_TRANSFORMER,
    INTERFACE_TRANSFORMER,
    MS_DATETIME_TRANSFORMER,
    NO_OP_TRANSFORMER,
    NONCE_TRANSFORMER,
    PUSH_TOKEN_TRANSFORMER,
    STATUS_TRANSFORMER,
    STRING_TRANSFORMER,
    TOPIC_TRANSFORMER,
    UNKNOWN_FLAG_TRANSFORMER,
    Capability,
    Interface,
    Nonce,
    Status,
    UnknownFlag,
    integer_transformer,
)


@dataclass
class UnknownCommand(APNsCommand):
    """Dummy command class to encapsulate unknown commands."""


class Direction(Flag):
    """Enumeration of the possible directions a command can be sent in."""

    CLIENT_BOUND = auto()
    SERVER_BOUND = auto()
    BIDIRECTIONAL = CLIENT_BOUND | SERVER_BOUND


COMMAND_MAP: Final[defaultdict[(int, Direction), type[APNsCommand]]] = defaultdict()
"""Map of command IDs to their packet classes."""

COMMAND_MAP.default_factory = lambda: register_command(-0x01, Direction.BIDIRECTIONAL)(UnknownCommand)

_T_co = TypeVar("_T_co", covariant=True, bound=type[APNsCommand])
_FIELDS: Final = "__dataclass_fields__"

Topic: TypeAlias = str | bytes

logger = getLogger(__name__)


def register_command(command_id: int, direction: Direction) -> Callable[_T_co, _T_co]:
    """Register an ``APNsCommand`` subclass with the command registry."""

    def wrapper(cls: _T_co) -> _T_co:
        """Set the command's command ID and register it with the command registry."""
        cls.command_id = command_id

        for d in direction:
            logger.debug(f"Registering command {cls.__name__} (0x{command_id:02X}) for {d.name} direction.")
            COMMAND_MAP[(command_id, d)] = cls

        return cls

    return wrapper


command = dataclass(repr=False)


@register_command(0x07, Direction.SERVER_BOUND)
@dataclass(repr=False)
class ConnectCommand(APNsCommand):
    """Command sent by the client to establish a connection with the APNs server."""

    push_token: Annotated[str | None, Item(0x01, PUSH_TOKEN_TRANSFORMER)]

    certificate: Annotated[Certificate | None, Item(0x0C, DER_CERTIFICATE_TRANSFORMER)]
    nonce: Annotated[Nonce | None, Item(0x0D, NONCE_TRANSFORMER)]
    signature: Annotated[bytes | None, Item(0x0E)]

    state: Annotated[Literal[b"\x01"], Item(0x02)] = b"\x01"
    flags: Annotated[UnknownFlag, Item(0x05, UNKNOWN_FLAG_TRANSFORMER)] = UnknownFlag.IS_ROOT
    interface: Annotated[Interface, Item(0x06, INTERFACE_TRANSFORMER)] = Interface.WIFI
    carrier: Annotated[str, Item(0x08, STRING_TRANSFORMER)] = "WiFi"
    os_version: Annotated[str, Item(0x09, STRING_TRANSFORMER)] = "10.6.4"
    os_build: Annotated[str, Item(0x0A, STRING_TRANSFORMER)] = "10.6.4"
    hardware_version: Annotated[str, Item(0x0B, STRING_TRANSFORMER)] = "windows1,1"
    protocol_version__: Annotated[int | None, Item(0x10, integer_transformer(2))] = 2
    redirect_count: Annotated[int, Item(0x11, integer_transformer(2))] = 0
    dns_resolve_time_ms: Annotated[int | None, Item(0x13, integer_transformer(2))] = None
    tls_handshake_time_ms: Annotated[int | None, Item(0x14, integer_transformer(2))] = None


@register_command(0x08, Direction.CLIENT_BOUND)
@dataclass(repr=False)
class ConnectResponseCommand(APNsCommand):
    """Command sent by the server in response to a client's connection request."""

    status: Annotated[Status, Item(0x01, STATUS_TRANSFORMER)]

    server_metadata__: Annotated[bytes | None, Item(0x02)]
    push_token: Annotated[str | None, Item(0x03, PUSH_TOKEN_TRANSFORMER)]
    max_message_size: Annotated[int | None, Item(0x04, integer_transformer(4))]
    protocol_version__: Annotated[int | None, Item(0x05, integer_transformer(4))]
    capabilities: Annotated[Capability | None, Item(0x06, CAPABILITIES_TRANSFORMER)]
    bad_nonce_time__: Annotated[datetime | None, Item(0x07, MS_DATETIME_TRANSFORMER)]
    large_message_size: Annotated[int | None, Item(0x08, integer_transformer(4))]
    server_time: Annotated[datetime | None, Item(0x0A, MS_DATETIME_TRANSFORMER)]
    geo_region: Annotated[str | None, Item(0x0B, STRING_TRANSFORMER)]
    unknown_timestamp__: Annotated[datetime | None, Item(0x0C, MS_DATETIME_TRANSFORMER)]


@register_command(0x09, Direction.SERVER_BOUND)
@dataclass(repr=False)
class FilterTopicsCommand(APNsCommand):
    """Command sent by the client to filter incoming push notifications based on topics."""

    push_token: Annotated[str, Item(0x01, PUSH_TOKEN_TRANSFORMER)]
    enabled_topics: Annotated[Collection[Topic] | None, Item(0x02, TOPIC_TRANSFORMER)] = field(
        default_factory=frozenset,
    )
    disabled_topics: Annotated[Collection[Topic] | None, Item(0x03, TOPIC_TRANSFORMER)] = field(
        default_factory=frozenset,
    )
    opportunity_topics: Annotated[Collection[Topic] | None, Item(0x04, TOPIC_TRANSFORMER)] = field(
        default_factory=frozenset,
    )
    paused_topics: Annotated[Collection[Topic] | None, Item(0x05, TOPIC_TRANSFORMER)] = field(default_factory=frozenset)


@register_command(0x0A, Direction.CLIENT_BOUND)
@dataclass(repr=False)
class ClientBoundPushNotificationCommand(APNsCommand):
    """Command sent by the server to deliver a push notification to a client."""

    push_token: Annotated[str, Item(0x01, PUSH_TOKEN_TRANSFORMER)]
    topic: Annotated[Topic, Item(0x02, TOPIC_TRANSFORMER)]
    payload: Annotated[bytes, Item(0x03, NO_OP_TRANSFORMER)]
    message_id: Annotated[int, Item(0x04, integer_transformer(4))]
    unknown__: Annotated[Literal[b"\x00"], Item(0x07, NO_OP_TRANSFORMER)] = b"\x00"


@register_command(0x0A, Direction.SERVER_BOUND)
@dataclass(repr=False)
class ServerBoundPushNotificationCommand(APNsCommand):
    """Command sent by the client to deliver a push notification to the server."""

    topic: Annotated[Topic, Item(0x01, TOPIC_TRANSFORMER)]
    push_token: Annotated[str, Item(0x02, PUSH_TOKEN_TRANSFORMER)]
    payload: Annotated[bytes, Item(0x03, NO_OP_TRANSFORMER)]
    message_id: Annotated[int, Item(0x04, integer_transformer(4))]
    unknown__: Annotated[Literal[b"\x00"], Item(0x07, NO_OP_TRANSFORMER)] = b"\x00"


@register_command(0x0B, Direction.BIDIRECTIONAL)
@dataclass(repr=False)
class PushNotificationAckCommand(APNsCommand):
    """Command sent by the recipient to acknowledge the receipt of a push notification."""

    message_id: Annotated[int, Item(0x04, integer_transformer(4))]
    status: Annotated[Status, Item(0x08, STATUS_TRANSFORMER)]


@register_command(0x0C, Direction.SERVER_BOUND)
@dataclass(repr=False)
class KeepAliveCommand(APNsCommand):
    """Command sent by the client to request confirmation that the connection is still alive."""

    connection_method: Annotated[str | None, Item(0x01, STRING_TRANSFORMER)]
    os_version: Annotated[str | None, Item(0x02, STRING_TRANSFORMER)]
    os_build: Annotated[str | None, Item(0x03, STRING_TRANSFORMER)]
    hardware_version: Annotated[str | None, Item(0x04, STRING_TRANSFORMER)]


@register_command(0x0D, Direction.CLIENT_BOUND)
@dataclass(repr=False)
class KeepAliveConfirmationCommand(APNsCommand):
    """Command sent by the server to confirm that the connection is still alive."""


@register_command(0x0E, Direction.CLIENT_BOUND)
@dataclass(repr=False)
class NoStorageCommand(APNsCommand):
    """Command sent by the server to inform the client that it has no storage available."""

    push_token: Annotated[str, Item(0x03, PUSH_TOKEN_TRANSFORMER)]


@register_command(0x0F, Direction.BIDIRECTIONAL)
@dataclass(repr=False)
class FlushCommand(APNsCommand):
    """Command sent by either the client or the server to flush the stream."""
