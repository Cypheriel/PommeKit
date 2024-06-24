#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel
"""Module containing serializers and deserializers for APNs protocol fields."""

from __future__ import annotations

from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum, IntFlag, auto
from functools import lru_cache, partial
from hashlib import sha1
from io import BytesIO
from typing import Callable, Final, Generic, Literal, Self, SupportsIndex, TypeVar

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import load_der_x509_certificate

from ..._util.crypto import randbytes
from ..protocol.topics import TOPIC_HASHES

__all__ = [
    "CAPABILITIES_TRANSFORMER",
    "DER_CERTIFICATE_TRANSFORMER",
    "INTERFACE_TRANSFORMER",
    "MS_DATETIME_TRANSFORMER",
    "NONCE_TRANSFORMER",
    "NO_OP_TRANSFORMER",
    "PUSH_TOKEN_TRANSFORMER",
    "STATUS_TRANSFORMER",
    "STRING_TRANSFORMER",
    "TOPIC_TRANSFORMER",
    "UNKNOWN_FLAG_TRANSFORMER",
    "Capability",
    "DataTransformer",
    "Interface",
    "Nonce",
    "Status",
    "UnknownFlag",
    "integer_transformer",
]

_T = TypeVar("_T")


def reverse_bits(data: bytes, byte_length: int = 4) -> bytes:
    """Reverse the bits of a byte sequence."""
    return int(f"{int.from_bytes(data):>0{byte_length * 8}b}"[::-1], 2).to_bytes(length=byte_length)


class DataTransformer(Generic[_T]):
    """A class responsible for serializing and deserializing bytes data."""

    def __init__(self: Self, deserializer: Callable[[bytes], _T], serializer: Callable[[_T], bytes]) -> None:
        """
        Initialize a new data transformer.

        :param deserializer: The function to deserialize bytes data.
        :param serializer: The function to serialize data to bytes.
        """
        self.deserialize = deserializer
        self.serialize = serializer


class BitMask(IntFlag):
    """Simple wrapper class to serialize and deserialize ``IntFlag`` in reverse bit order."""

    @classmethod
    def from_bytes(
        cls: type[Self],
        bytes_: bytes,
        byteorder: Literal["big", "little"] = "big",
        *,
        signed: bool = False,
    ) -> Self:
        return cls(int.from_bytes(reverse_bits(bytes_), byteorder, signed=signed))

    def to_bytes(
        self: Self,
        length: SupportsIndex = 1,
        byteorder: Literal["little", "big"] = "big",
        *,
        signed: bool = False,
    ) -> bytes:
        return reverse_bits(super().to_bytes(length, byteorder, signed=signed))


class UnknownFlag(BitMask):
    """Unknown device flags sent by the device in the initial connection."""

    NONE = 0x00

    UNKNOWN_00 = auto()
    UNKNOWN_01 = auto()
    UNKNOWN_02 = auto()
    UNKNOWN_03 = auto()
    UNKNOWN_04 = auto()
    UNKNOWN_05 = auto()
    UNKNOWN_06 = auto()
    UNKNOWN_07 = auto()

    UNKNOWN_08 = auto()
    UNKNOWN_09 = auto()
    UNKNOWN_0A = auto()
    UNKNOWN_0B = auto()
    UNKNOWN_0C = auto()
    UNKNOWN_0D = auto()
    UNKNOWN_0E = auto()
    UNKNOWN_0F = auto()

    UNKNOWN_10 = auto()
    UNKNOWN_11 = auto()
    UNKNOWN_12 = auto()
    UNKNOWN_13 = auto()
    UNKNOWN_14 = auto()
    UNKNOWN_15 = auto()
    UNKNOWN_16 = auto()
    UNKNOWN_17 = auto()

    UNKNOWN_18 = auto()
    UNKNOWN_19 = auto()
    UNKNOWN_1A = auto()
    UNKNOWN_1B = auto()
    UNKNOWN_1C = auto()
    IS_ROOT = auto()
    """Set if the device is connecting as root for the first time."""
    UNKNOWN_1E = auto()
    UNKNOWN_1F = auto()


class Capability(BitMask):
    """Device capabilities returned by the server upon initial connection."""

    NONE = 0x00

    UNKNOWN_00 = auto()
    UNKNOWN_01 = auto()
    UNKNOWN_02 = auto()
    UNKNOWN_03 = auto()
    UNKNOWN_04 = auto()
    UNKNOWN_05 = auto()
    UNKNOWN_06 = auto()
    UNKNOWN_07 = auto()

    UNKNOWN_08 = auto()
    UNKNOWN_09 = auto()
    UNKNOWN_0A = auto()
    UNKNOWN_0B = auto()
    UNKNOWN_0C = auto()
    UNKNOWN_0D = auto()
    UNKNOWN_0E = auto()
    UNKNOWN_0F = auto()

    UNKNOWN_10 = auto()
    UNKNOWN_11 = auto()
    UNKNOWN_12 = auto()
    UNKNOWN_13 = auto()
    UNKNOWN_14 = auto()
    UNKNOWN_15 = auto()
    UNKNOWN_16 = auto()
    UNKNOWN_17 = auto()

    UNKNOWN_18 = auto()
    UNKNOWN_19 = auto()
    UNKNOWN_1A = auto()
    UNKNOWN_1B = auto()
    UNKNOWN_1C = auto()
    UNKNOWN_1D = auto()
    UNKNOWN_1E = auto()
    DUAL_CHANNEL = auto()


class Interface(IntEnum):
    """Interface used to connect to the APNs server."""

    CELLULAR = 0x00
    WIFI = 0x01


class Status(IntEnum):
    """Status codes returned by the server in response to a client's connection request."""

    OK = 0x00
    ERROR = 0x02


@dataclass
class Nonce:
    """A simple nonce used for various purposes."""

    nonce_time: datetime = field(default_factory=lambda: datetime.now().astimezone())
    random_bytes: bytes = field(default_factory=lambda: randbytes(8))
    prefix: bytes = b"\x00"

    @classmethod
    def from_bytes(cls: type[Self], data: bytes, timestamp_size: int = 8, random_bytes_length: int = 8) -> Self:
        """Deserialize a nonce from bytes."""
        stream = BytesIO(data)
        stream.read(1)  # Skip the first byte
        return cls(
            nonce_time=datetime.fromtimestamp(int.from_bytes(stream.read(timestamp_size)) / 1_000, tz=timezone.utc),
            random_bytes=stream.read(random_bytes_length),
        )

    def __bytes__(self: Self) -> bytes:
        """Serialize the nonce to bytes."""
        result = self.prefix
        result += int(self.nonce_time.timestamp() * 1_000).to_bytes(8)
        result += self.random_bytes
        return result


# -- Transformers --
NO_OP_TRANSFORMER: Final = DataTransformer(lambda data: data, lambda value: value)
PUSH_TOKEN_TRANSFORMER: Final = DataTransformer(lambda data: b64encode(data).decode(), b64decode)
UNKNOWN_FLAG_TRANSFORMER: Final = DataTransformer(
    UnknownFlag.from_bytes,
    partial(UnknownFlag.to_bytes, length=4),
)
INTERFACE_TRANSFORMER: Final = DataTransformer(Interface.from_bytes, partial(int.to_bytes, length=1))
STRING_TRANSFORMER: Final = DataTransformer(partial(bytes.decode, encoding="utf-8"), str.encode)
DER_CERTIFICATE_TRANSFORMER: Final = DataTransformer(
    load_der_x509_certificate,
    lambda certificate: certificate.public_bytes(encoding=Encoding.DER),
)
NONCE_TRANSFORMER: Final = DataTransformer(Nonce.from_bytes, bytes)
STATUS_TRANSFORMER: Final = DataTransformer(Status.from_bytes, partial(int.to_bytes, length=1))
CAPABILITIES_TRANSFORMER: Final = DataTransformer(Capability.from_bytes, partial(Capability.to_bytes, length=4))
MS_DATETIME_TRANSFORMER: Final = DataTransformer(
    lambda data: datetime.fromtimestamp(int.from_bytes(data) / 1_000, tz=timezone.utc),
    lambda value: int(value.timestamp() * 1_000).to_bytes(length=8),
)
TOPIC_TRANSFORMER: Final = DataTransformer(
    lambda data: TOPIC_HASHES.get(data, data),
    lambda value: sha1(value.encode(), usedforsecurity=False).digest() if isinstance(value, str) else value,
)


@lru_cache
def integer_transformer(size: int) -> DataTransformer[int]:
    """Create a variable-length integer transformer."""
    return DataTransformer(int.from_bytes, partial(int.to_bytes, length=size))
