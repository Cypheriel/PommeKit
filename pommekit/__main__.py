#  Copyright (C) 2024  Cypheriel
"""Main entrypoint for the PommeKit CLI."""

from ._cli.main_command import app

__entrypoint__ = app
if __name__ == "__main__":
    __entrypoint__()
