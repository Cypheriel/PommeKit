#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel

import asyncio
from collections.abc import Hashable
from enum import Enum, auto
from logging import getLogger
from typing import Annotated, Awaitable, Callable

logger = getLogger(__name__)


def _verify_callback(func: Callable[[...], Awaitable[None]]) -> None:
    if not callable(func):
        msg = f"Listener must be a callable, got {type(func).__name__}!"
        raise TypeError(msg)

    if not asyncio.iscoroutinefunction(func):
        msg = f"Listener must be a coroutine function, got {type(func).__name__}!"
        raise TypeError(msg)


def _get_identifier_name(identifier: Annotated[Hashable, "Identifier"]) -> str:
    if isinstance(identifier, (bytes, str)):
        identifier_name = f"{identifier!r}"
    elif isinstance(identifier, Enum):
        identifier_name = f"{identifier.name}"
    elif hasattr(identifier, "__qualname__"):
        identifier_name = f"{identifier.__qualname__}"
    else:
        identifier_name = f"{identifier}"

    return identifier_name


class EventType(Enum):
    COMMAND = auto()
    TOPIC = auto()
    CONNECT = auto()
    OTHER = auto()


class EventListener:
    def __init__(self: "EventListener") -> None:
        self._callback_map: dict[
            tuple[EventType, Annotated[Hashable, "Identifier"]],
            list[Callable[[...], Awaitable[None]]],
        ] = {}

    def _register_event_listener(
        self: "EventListener",
        event_type: EventType,
        identifier: Annotated[Hashable, "Identifier"],
        *,
        internal: bool = True,
    ) -> Callable:
        def decorator(func: Callable) -> Callable:
            _verify_callback(func)
            internal_s = "internal " if internal else ""
            identifier_name = _get_identifier_name(identifier)
            logger.debug(
                f"Registering {internal_s}listener {func.__name__}() for {event_type.name} event {identifier_name}.",
            )

            if (event_type, identifier) in self._callback_map:
                self._callback_map[event_type, identifier].append(func)
            else:
                self._callback_map[event_type, identifier] = [func]

            return func

        return decorator

    async def _trigger_event(
        self: "EventListener",
        event_type: EventType,
        identifier: Annotated[Hashable, "Identifier"],
        *args: ...,
        **kwargs: ...,
    ) -> None:
        logger.debug(f"Triggering {event_type.name} event {_get_identifier_name(identifier)}.")

        listeners = self._callback_map.get((event_type, identifier))

        if listeners:
            await asyncio.gather(*(listener(*args, **kwargs) for listener in listeners))
