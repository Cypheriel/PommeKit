#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel
from __future__ import annotations

from typing import Self


class GrandSlamError(Exception):
    def __init__(
        self: Self,
        message: str = "",
        error_code: int | None = None,
        error_message: str = "Error message not supplied.",
    ) -> None:
        """Exception raised when an error occurs during a GrandSlam operation."""
        status_message = ""

        if error_code is not None:
            status_message = f" ({error_code}: {error_message})"

        super().__init__(f"{message}{status_message}")
