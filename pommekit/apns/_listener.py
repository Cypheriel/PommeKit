#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel
"""APNs event listener for handling APNs commands and topic-specific push notifications."""

from __future__ import annotations

from hashlib import sha1
from typing import TYPE_CHECKING, Callable, Self

from .._util.event_listener import EventListener, EventType

if TYPE_CHECKING:
    from ..apns._protocol.packet import APNsCommand


class APNsListener(EventListener):
    """An event listener for APNs commands and topic-specific push notifications."""

    def __init__(self: Self) -> None:
        """Initialize the APNs listener."""
        super().__init__()
        self.enabled_topics: list[bytes] = []
        """A list of enabled topic hashes that will eventually be used to filter incoming push notifications."""

    def _register_command_listener(
        self: Self,
        command: type[APNsCommand],
        *,
        internal: bool = True,
    ) -> Callable[[APNsCommand], None]:
        """Register an internal listener for a specific APNs command."""
        return self._register_event_listener(EventType.COMMAND, command, internal=internal)

    def register_command_listener(self: Self, command: type[APNsCommand]) -> Callable[[APNsCommand], None]:
        """Register a listener for a specific APNs command."""
        return self._register_command_listener(command, internal=False)

    def _register_topic_listener(self: Self, topic: str | bytes, *, internal: bool = True) -> Callable:
        """Register an internal listener for a specific topic."""
        topic_hash = sha1(topic.encode(), usedforsecurity=False).digest() if isinstance(topic, str) else topic
        self.enabled_topics.append(topic_hash)
        return self._register_event_listener(EventType.TOPIC, topic_hash, internal=internal)

    def register_topic_listener(self: Self, topic: str | bytes) -> Callable:
        """Register a listener for a specific topic."""
        return self._register_topic_listener(topic, internal=False)

    def _register_connect_listener(self: Self, *, internal: bool = True) -> Callable:
        """Register an internal listener for the APNs connection event."""
        return self._register_event_listener(EventType.CONNECT, EventType.CONNECT.name, internal=internal)

    def register_connect_listener(self: Self) -> Callable:
        """Register a listener for the APNs connection event."""
        return self._register_connect_listener(internal=False)
