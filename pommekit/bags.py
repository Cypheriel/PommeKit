#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel
"""Module containing functions to fetch Apple's APNs and IDS bags."""

from __future__ import annotations

import plistlib
from functools import lru_cache
from logging import getLogger

from httpx import Client

logger = getLogger(__name__)
client = Client(
    verify=False,  # noqa: S501
)


class BagFetchError(Exception):
    """Exception raised when a bag fetch fails."""


@lru_cache
def get_apns_bag() -> dict[str, str]:
    """Fetch Apple's APNs bag."""
    response = client.get("https://init.push.apple.com/bag")

    if not response.is_success:
        msg = f"Failed to fetch APNs bag! Status: {response.status_code}"
        raise BagFetchError(msg)

    return plistlib.loads(response.content)


@lru_cache
def get_ids_bag() -> dict[str, str]:
    """Fetch Apple's IDS bag."""
    response = client.get("https://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=3")

    if not response.is_success:
        msg = "Failed to fetch IDS bag!"
        raise BagFetchError(msg)

    return plistlib.loads(plistlib.loads(response.content)["bag"])


class _Bags:
    @property
    def apns_bag(self):
        if not self._apns_bag:
            self._apns_bag = get_apns_bag()

        return self._apns_bag

    @property
    def ids_bag(self):
        if not self._ids_bag:
            self._ids_bag = get_ids_bag()

        return self._ids_bag

    def __init__(self):
        self._apns_bag = {}
        self._ids_bag = {}
