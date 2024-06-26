#  Copyright (C) 2024  Cypheriel
"""Main entrypoint for the PommeKit CLI."""

import logging
from datetime import datetime
from sys import stderr
from typing import Annotated

import typer
from rich.console import Console
from rich.logging import RichHandler

from ._cli import device
from ._cli.util.app_dirs import USER_LOG_DIR
from ._cli.util.rich_console import console

app = typer.Typer()
app.add_typer(device.app)
app.add_typer(device.app, name=device.__ALIAS__, hidden=True)

logger = logging.getLogger(__name__)


def _setup_logging(level: int) -> None:
    logging_file = USER_LOG_DIR / datetime.now().astimezone().strftime("%Y-%m-%d_%H-%M-%S.log")
    logging_file.parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[
            RichHandler(
                console=Console(file=stderr),
            ),
            logging.FileHandler(logging_file),
        ],
    )


@app.callback(no_args_is_help=True)
def main(
    *,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose logging."),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Enable quiet logging."),
    ] = False,
    silent: Annotated[
        bool,
        typer.Option("--silent", help="Completely disable logging."),
    ] = False,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", envvar="NO_COLOR", help="Disable color output."),
    ] = False,
) -> None:
    """PommeKit - Python library with various tools for interacting with Apple services and APIs."""
    if (verbose, quiet, silent).count(True) > 1:
        typer.echo("Can only enable one of --verbose, --quiet, or --silent.", err=True)
        raise typer.Abort

    if not any((verbose, quiet, silent)):
        _setup_logging(logging.INFO)
        logger.debug("Logging initialized at INFO level.")

    if verbose:
        _setup_logging(logging.DEBUG)
        logger.debug("Logging initialized at DEBUG level.")

    if quiet:
        _setup_logging(logging.CRITICAL)
        logger.debug("Logging initialized at CRITICAL level.")

    if silent:
        logging.disable(logging.CRITICAL)

    if no_color:
        console.no_color = True


__entrypoint__ = app
if __name__ == "__main__":
    __entrypoint__()
