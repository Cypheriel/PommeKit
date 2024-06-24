#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ExponentialBackoff:
    base_delay: float = 1.0
    max_delay: float = 60.0
    max_retries: int = 10

    _retries: int = 0
    _delay: float = 0.0

    def next(self: ExponentialBackoff) -> float:
        if self._retries >= self.max_retries:
            msg = "Max retries exceeded"
            raise StopIteration(msg)

        self._delay = min(self.base_delay * 2**self._retries, self.max_delay)
        self._retries += 1
        return self._delay
