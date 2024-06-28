#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel
"""
Simple mapping of known topics to their hashed values.

>>> TOPIC_HASHES[sha1(b"com.apple.madrid", usedforsecurity=False).digest()] == "com.apple.madrid"
True
"""

from __future__ import annotations

from hashlib import sha1
from typing import Final

_KNOWN_TOPICS: Final = frozenset(
    {
        "com.apple.madrid",
    },
)
TOPIC_HASHES: Final[dict[bytes, str]] = {
    sha1(topic.encode(), usedforsecurity=False).digest(): topic for topic in _KNOWN_TOPICS
}
