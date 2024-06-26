#  Copyright (C) 2024  Cypheriel
from __future__ import annotations

import os
from dataclasses import dataclass
from getpass import getuser
from logging import getLogger
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, ClassVar

import typer

from .._util.aio import run_async
from ..device import Device, OperatingSystem
from .util.app_dirs import USER_DATA_DIR
from .util.device_utils import fetch_device
from .util.rich_console import console
from .util.selection import get_selected_device, set_selected_device

if TYPE_CHECKING:
    from collections.abc import Generator

__ALIAS__ = "ds"


def list_devices(ctx: typer.Context, incomplete: str) -> Generator[str]:
    path = Path(ctx.params.get("path", os.environ.get("POMMEKIT_DEVICE_PATH", DeviceOptions.save_path)))

    for device_path in path.iterdir():
        if (
            device_path.is_dir()
            and (device_path / "device_info.json").is_file()
            and device_path.name.startswith(incomplete)
        ):
            yield device_path.name


SERIAL_HELP = "The serial number of the device."
SerialArgument = Annotated[
    str,
    typer.Argument(help="The serial number of the device.", show_default=False, autocompletion=list_devices),
]

app = typer.Typer()
logger = getLogger(__name__)


@dataclass(kw_only=True)
class DeviceOptions:
    save_path: ClassVar[Path] = USER_DATA_DIR / "Devices"
    selected_device: ClassVar[str | None] = None


@app.command(name="list", help="List installed devices.")
@app.command(name="ls", hidden=True)
def list_() -> None:
    if not DeviceOptions.save_path.is_dir():
        typer.echo("No devices found.", err=True)
        raise typer.Exit(1)

    found = False
    for device_path in DeviceOptions.save_path.iterdir():
        dev = fetch_device(device_path.parent, device_path.name)

        if dev is None:
            continue

        provisioned = " ([green]Provisioned[/])" if dev.requires_provisioning is False else ""
        selected = " ([blue]Selected[/])" if DeviceOptions.selected_device == dev.hardware_serial else ""
        console.print(f"{dev.name} - {dev.hardware_serial}{provisioned}{selected}")
        found = True

    if not found:
        typer.echo("No devices found.", err=True)


@app.command(help="Get information about a device.")
@app.command(name="if", hidden=True)
def info(
    serial_number: SerialArgument = DeviceOptions.selected_device,
) -> None:
    if serial_number is None:
        typer.echo("No device selected. Specify a device using `--serial-number` or the `device sel` command", err=True)
        raise typer.Exit(1)

    dev = fetch_device(DeviceOptions.save_path, serial_number)
    typer.echo(
        f"Device: {dev.name}\n"
        f"Serial Number: {dev.hardware_serial}\n"
        f"UID: {dev.identifier}\n"
        f"Product Type: {dev.hardware_version}\n"
        f"Product Version: {dev.os_version}\n"
        f"Build Version: {dev.os_build}\n"
        f"Device Class: {dev.operating_system.value}\n",
    )


@app.command(help="Create a new device.")
@app.command(name="create", hidden=True)
@app.command(name="new", hidden=True)
@run_async
async def add(
    device_name: Annotated[
        str,
        typer.Option(
            prompt=True,
            help="The name of the device.",
        ),
    ] = f"{getuser()}'s PC",
    serial_number: Annotated[
        str,
        typer.Option(
            prompt=True,
            help=SERIAL_HELP,
            autocompletion=list_devices,
        ),
    ] = "WindowSerial",
    operating_system: Annotated[
        OperatingSystem,
        typer.Option(
            prompt=True,
            help="The operating system of the device.",
        ),
    ] = OperatingSystem.WINDOWS,
    os_version: Annotated[
        str,
        typer.Option(
            prompt="OS version",
            help="The version of the operating system.",
        ),
    ] = "10.6.4",
    os_build: Annotated[
        str,
        typer.Option(
            prompt="OS build",
            help="The build of the operating system.",
        ),
    ] = "10.6.4",
    hardware_version: Annotated[
        str,
        typer.Option(
            prompt=True,
            help="The hardware version of the device.",
        ),
    ] = "windows1,1",
    *,
    skip_provisioning: Annotated[
        bool,
        typer.Option(
            "--skip-provisioning",
            "-s",
            help="Skip Anisette provisioning.",
        ),
    ] = False,
) -> None:
    if fetch_device(DeviceOptions.save_path, serial_number) is not None:
        typer.confirm("Device already exists... Overwrite?", abort=True)

    dev = Device(
        name=device_name,
        hardware_serial=serial_number,
        operating_system=operating_system,
        os_version=os_version,
        os_build=os_build,
        hardware_version=hardware_version,
        save_path=DeviceOptions.save_path,
    )

    dev.save()

    if dev.requires_provisioning is False or skip_provisioning is True:
        typer.echo("Skipping Anisette provisioning.")
        return

    typer.echo("Starting Anisette provisioning...")
    await dev.start_provisioning()

    typer.echo("Fetching push credentials from Albert...")
    if dev.requires_push_credentials:
        await dev.get_push_credentials()

    dev.save()


@app.command(help="Remove a device.")
@app.command(name="rm", hidden=True)
@app.command(name="delete", hidden=True)
@run_async
async def remove() -> None: ...


@app.command(help="Provision a device through Anisette.")
@app.command(name="prov", hidden=True)
@run_async
async def provision(
    serial_number: SerialArgument,
    *,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Force a re-provision of the device.",
        ),
    ] = False,
) -> None:
    dev = fetch_device(DeviceOptions.save_path, serial_number)

    if force is True:
        logger.warning(
            "Re-provisioning the Anisette data and/or push credentials may cause issues with authenticated users!",
        )

    if dev.requires_provisioning is True or force is True:
        await dev.start_provisioning()

    if dev.requires_push_credentials is True or force is True:
        await dev.get_push_credentials()

    else:
        logger.error("Device is already provisioned. Use --force to re-provision.")
        raise typer.Abort

    dev.save()


@app.command(help="Select this device for use with other PommeKit commands.")
@app.command(name="sel", hidden=True)
def select(serial_number: SerialArgument = None) -> None:
    if serial_number is None:
        if DeviceOptions.selected_device is None:
            raise typer.Exit

        typer.echo(DeviceOptions.selected_device)
        raise typer.Exit

    set_selected_device(DeviceOptions.save_path, serial_number)


@app.callback(no_args_is_help=True, hidden=False)
def device(
    path: Annotated[
        Path | None,
        typer.Option(
            "--path",
            "-p",
            envvar="POMMEKIT_DEVICE_PATH",
            help="The path to save/load device data to.",
        ),
    ] = DeviceOptions.save_path,
) -> None:
    DeviceOptions.save_path = path
    DeviceOptions.selected_device = get_selected_device(path)

    logger.debug(f"Device path set to '{DeviceOptions.save_path}'.")
    logger.debug(f"Selected device set to '{DeviceOptions.selected_device}'.")
