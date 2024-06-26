#  Copyright (C) 2024  Cypheriel
import asyncio
from collections.abc import Callable, Coroutine
from functools import wraps


def run_async(func: Callable[..., Coroutine]) -> Callable:
    @wraps(func)
    def wrapper(*args: ..., **kwargs: ...) -> ...:
        return asyncio.run(func(*args, **kwargs))

    return wrapper
