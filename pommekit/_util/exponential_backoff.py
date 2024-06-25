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
        """
        Return the next delay in seconds for the exponential backoff.

        >>> backoff = ExponentialBackoff(base_delay=4.0)
        >>> backoff.next()
        4.0
        >>> backoff.next()
        8.0
        >>> backoff.next()
        16.0

        :return: The next delay in seconds.
        """
        if self._retries >= self.max_retries:
            msg = "Max retries exceeded"
            raise StopIteration(msg)

        self._delay = min(self.base_delay * 2**self._retries, self.max_delay)
        self._retries += 1
        return self._delay
