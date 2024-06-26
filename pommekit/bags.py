#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel
"""Module containing functions to fetch Apple's APNs and IDS bags."""

from __future__ import annotations

import plistlib
from functools import lru_cache
from logging import getLogger
from typing import Final

from httpx import AsyncClient

logger = getLogger(__name__)
client = AsyncClient(
    verify=False,  # noqa: S501
)


class BagFetchError(Exception):
    """Exception raised when a bag fetch fails."""


@lru_cache
async def get_apns_bag() -> dict[str, str]:
    """Fetch Apple's APNs bag."""
    response = await client.get("https://init.push.apple.com/bag")

    if not response.is_success:
        msg = f"Failed to fetch APNs bag! Status: {response.status_code}"
        raise BagFetchError(msg)

    return plistlib.loads(response.content)


@lru_cache
async def get_ids_bag() -> dict[str, str]:
    """Fetch Apple's IDS bag."""
    response = await client.get("https://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=3")

    if not response.is_success:
        msg = "Failed to fetch IDS bag!"
        raise BagFetchError(msg)

    return plistlib.loads(plistlib.loads(response.content)["bag"])


apns_bag: Final = {}
ids_bag: Final = {}


async def _fetch_bags() -> None:
    apns_bag.update(await get_apns_bag())
    ids_bag.update(await get_ids_bag())
