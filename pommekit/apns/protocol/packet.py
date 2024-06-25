#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel
"""Module containing the base class responsible for serializing and deserializing APNs command packets."""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import MISSING, dataclass, field, fields, is_dataclass
from io import BytesIO
from logging import getLogger
from typing import Annotated, ClassVar, Final, Self, TypeVar, get_origin

from ..protocol.transformers import NO_OP_TRANSFORMER, DataTransformer

_T = TypeVar("_T")

# Packet protocol definitions
# Format: [COMMAND_ID][COMMAND_LENGTH][ITEM_ID][ITEM_LENGTH][ITEM_DATA][ITEM_ID][ITEM_LENGTH][ITEM_DATA]...
COMMAND_ID_BYTES: Final = 1
COMMAND_LENGTH_BYTES: Final = 4
ITEM_ID_BYTES: Final = 1
ITEM_LENGTH_BYTES: Final = 2

logger = getLogger(__name__)


def _serialize_item(metadata: Item, value: _T) -> bytes:
    """Serialize an item using the provided metadata and value."""
    serialized_value = metadata.transformer.serialize(value)
    return (
        metadata.item_id.to_bytes(ITEM_ID_BYTES) + len(serialized_value).to_bytes(ITEM_LENGTH_BYTES) + serialized_value
    )


def _get_default_field_values(cls: type) -> dict[str, ...]:
    """Get the default values for all fields in the command class."""
    if is_dataclass(cls) is False:
        msg = "The provided class is not a dataclass!"
        raise ValueError(msg)

    # noinspection PyDataclass
    return {
        command_field.name: (
            command_field.default
            if command_field.default is not MISSING
            else command_field.default_factory()
            if callable(command_field.default_factory)
            else None
        )
        for command_field in fields(cls)
    }


@dataclass
class Item:
    """Simple dataclass to encapsulate metadata about a command field."""

    item_id: int
    transformer: DataTransformer = NO_OP_TRANSFORMER


@dataclass(kw_only=True)
class APNsCommand:
    """Base class for APNs commands."""

    command_id: ClassVar[int]

    unknown_items: list[tuple[int, bytes]] = field(default_factory=list)
    """List of items that could not be deserialized. Each item is a tuple of ``(item_id, item_data)``."""

    def __bytes__(self: Self) -> bytes:
        """Serialize the command to bytes."""
        if not hasattr(self, "command_id"):
            msg = "Missing command ID in command. Please register the command first!"
            raise ValueError(msg)

        # Sort fields by item ID
        sorted_fields = sorted(
            fields(self),
            key=lambda f: f.type.__metadata__[0].item_id if get_origin(f.type) is Annotated else -1,
        )

        item_data = b""

        for command_field in sorted_fields:
            if get_origin(command_field.type) is not Annotated:
                continue

            metadata = command_field.type.__metadata__
            if len(metadata) != 1 or not isinstance(metadata[0], Item):
                continue

            metadata = metadata[0]

            value = getattr(self, command_field.name)

            if value is None:
                continue

            if isinstance(value, Collection) and not isinstance(value, (str, bytes)):
                for item in value:
                    item_data += _serialize_item(metadata, item)

            else:
                item_data += _serialize_item(metadata, value)

        return self.command_id.to_bytes(COMMAND_ID_BYTES) + len(item_data).to_bytes(COMMAND_LENGTH_BYTES) + item_data

    @classmethod
    def from_bytes(cls: type[Self], data: bytes, *, includes_header: bool = False) -> type[Self]:
        """
        Deserialize a command from bytes.

        :param data: The bytes to deserialize.
        :param includes_header: Whether the data includes the command ID and length.
        """
        stream = BytesIO(data)

        if includes_header:
            command_id = int.from_bytes(stream.read(COMMAND_ID_BYTES))
            if command_id != cls.command_id:
                msg = "The provided data does not match the command ID of this class!"
                raise ValueError(msg)

            stream.read(COMMAND_LENGTH_BYTES)  # Skip the length field

        unknown_items: list[tuple[int, bytes]] = []
        values = _get_default_field_values(cls)

        while stream.tell() < len(data):
            item_id = int.from_bytes(stream.read(ITEM_ID_BYTES))
            item_length = int.from_bytes(stream.read(ITEM_LENGTH_BYTES))
            item_data = stream.read(item_length)

            for command_field in fields(cls):
                if get_origin(command_field.type) is not Annotated:
                    continue

                metadata = command_field.type.__metadata__
                if len(metadata) != 1 or not isinstance(metadata[0], Item):
                    continue

                metadata = metadata[0]

                if metadata.item_id != item_id:
                    continue

                current_value = values[command_field.name]
                # If the field is a collection, append the deserialized item to the current value via restructuring
                if isinstance(current_value, Collection) and not isinstance(current_value, (str, bytes)):
                    if command_field.default_factory is MISSING:
                        msg = "Collection fields must have a default factory!"
                        raise ValueError(msg)

                    values[command_field.name] = command_field.default_factory(
                        (
                            *current_value,
                            *command_field.default_factory((metadata.transformer.deserialize(item_data),)),
                        ),
                    )

                # If the field is not a collection, set the value directly — this will overwrite any previous value
                else:
                    values[command_field.name] = metadata.transformer.deserialize(item_data)

        # noinspection PyArgumentList
        return cls(**values, unknown_items=unknown_items)

    def __repr__(self: Self) -> str:
        """Similar to the default repr, but with tabs and newlines for readability and excludes None values."""
        result = f"{self.__class__.__name__}(\n\t"

        attrs = [f"{attr.name}={value!r}" for attr in fields(self) if (value := getattr(self, attr.name)) is not None]

        result += ",\n\t".join(attrs).strip() + "\n)"
        return result

    def bytes_debug_repr(self: Self) -> str:
        """Return a debug-focused representation of the command's raw bytes."""
        stream = BytesIO(bytes(self))
        command_id = stream.read(COMMAND_ID_BYTES)
        command_length = stream.read(COMMAND_LENGTH_BYTES)
        result = (
            f"COMMAND_ID = {command_id} (0x{self.command_id:02X})\n"
            f"COMMAND_LENGTH = {command_length} ({int.from_bytes(command_length)})"
        )

        while stream.tell() < len(bytes(self)):
            item_id_bytes = stream.read(ITEM_ID_BYTES)
            item_id = int.from_bytes(item_id_bytes)

            item_length_bytes = stream.read(ITEM_LENGTH_BYTES)
            item_length = int.from_bytes(item_length_bytes)

            item_data = stream.read(item_length)

            result += (
                "\n"
                f"ITEM_ID = {item_id_bytes} (0x{item_id:02X})\n"
                f"\tITEM_LENGTH = {item_length_bytes} ({item_length})\n"
                f"\tITEM_DATA = {item_data}\n"
            )

        return result
