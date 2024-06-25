#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel

from __future__ import annotations

from urllib.parse import ParseResult, urlparse


def replace_url(url: str | ParseResult, scheme: str | None = None, path: str | None = None) -> str:
    """
    Replace the scheme and/or path of a URL.

    >>> replace_url("https://example.com/path/to/resource", scheme="wss", path="/new/path")
    'wss://example.com/new/path'

    :param url: The URL to replace the scheme and/or path of.
    :param scheme: The new scheme to use. If `None`, the scheme will not be changed.
    :param path: The new path to use. If `None`, the path will not be changed.
    :return: The URL with the new scheme and/or path.
    """
    parsed = url if isinstance(url, ParseResult) else urlparse(url)
    if scheme is not None:
        parsed = parsed._replace(scheme=scheme)
    if path is not None:
        parsed = parsed._replace(path=path)

    return parsed.geturl()
