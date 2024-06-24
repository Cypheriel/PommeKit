#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel

from __future__ import annotations

from urllib.parse import ParseResult, urlparse


def replace_url(url: str | ParseResult, scheme: str | None = None, path: str | None = None) -> str:
    parsed = url if isinstance(url, ParseResult) else urlparse(url)
    if scheme is not None:
        parsed = parsed._replace(scheme=scheme)
    if path is not None:
        parsed = parsed._replace(path=path)

    return parsed.geturl()
