#  Copyright (C) 2024  Cypheriel
import os
from base64 import b64encode
from collections.abc import Generator
from getpass import getuser
from logging import getLogger
from pathlib import Path
from typing import Annotated, Final, Optional

import typer
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA1

from .._util.aio import run_async
from ..albert import request_push_certificate
from ..anisette.v3 import AnisetteV3Provider
from ..apns import APNsClientStream
from ..apns.commands import ConnectCommand, ConnectResponseCommand
from ..apns.types import Nonce
from ..device import APNsCredentialsComponent, Device, DeviceInfoComponent, MachineDataComponent, OperatingSystem
from . import CLIOptions
from .util.device_utils import fetch_device
from .util.rich_console import console
from .util.selection import get_selected_device, set_selected_device

__ALIAS__ = "ds"


def list_devices(ctx: typer.Context, incomplete: str) -> Generator[str]:
    path = Path(ctx.params.get("path", os.environ.get("POMMEKIT_DEVICE_PATH", CLIOptions.device_path)))

    for device_path in path.iterdir():
        if (
            device_path.is_dir()
            and (device_path / "device_info.json").is_file()
            and device_path.name.startswith(incomplete)
        ):
            yield device_path.name


SERIAL_HELP: Final = "The serial number of the device."
SerialArgument = Annotated[
    str,
    typer.Argument(help="The serial number of the device.", show_default=False, autocompletion=list_devices),
]

app = typer.Typer()
logger = getLogger(__name__)


@app.command(name="list", help="List installed devices.")
@app.command(name="ls", hidden=True)
def list_() -> None:
    if not CLIOptions.device_path.is_dir():
        typer.echo("No devices found.", err=True)
        raise typer.Exit(1)

    found = False
    for device_path in CLIOptions.device_path.iterdir():
        dev = fetch_device(device_path.parent, device_path.name)

        if dev is None:
            continue

        provisioned = " ([green]Provisioned[/])" if dev.machine_data.requires_provisioning is False else ""
        selected = " ([blue]Selected[/])" if CLIOptions.selected_device == dev.machine_data.serial_number else ""
        console.print(f"{dev.device_info.name} - {dev.machine_data.serial_number}{provisioned}{selected}")
        found = True

    if not found:
        typer.echo("No devices found.", err=True)


@app.command(help="Get information about a device.")
@app.command(name="if", hidden=True)
def info(
    serial_number: SerialArgument = None,
) -> None:
    serial_number = serial_number or CLIOptions.selected_device
    if serial_number is None:
        typer.echo("No device selected. Specify a device using `--serial-number` or the `device sel` command", err=True)
        raise typer.Exit(1)

    dev = fetch_device(CLIOptions.device_path, serial_number)
    typer.echo(
        f"Device: {dev.device_info.name}\n"
        f"Serial Number: {dev.machine_data.serial_number}\n"
        f"UID: {dev.machine_data.identifier}\n"
        f"Model Version: {dev.device_info.model_number}\n"
        f"Product Version: {dev.device_info.operating_system_version}\n"
        f"Build Version: {dev.device_info.operating_system_build}\n"
        f"Device Class: {dev.device_info.operating_system}\n",
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
    udid: Annotated[
        Optional[str],
        typer.Option(
            help="The UDID of the device.",
        ),
    ] = None,
    imei: Annotated[
        Optional[str],
        typer.Option(
            help="The IMEI of the device.",
        ),
    ] = None,
    meid: Annotated[
        Optional[str],
        typer.Option(
            help="The MEID of the device.",
        ),
    ] = None,
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
    model_number: Annotated[
        Optional[str],
        typer.Option(
            help="The model number of the device.",
        ),
    ] = None,
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
    if fetch_device(CLIOptions.device_path, serial_number) is not None:
        typer.confirm("Device already exists... Overwrite?", abort=True)

    if operating_system == OperatingSystem.IOS:
        udid = udid or typer.prompt("UDID")
        imei = imei or typer.prompt("IMEI")
        meid = meid or typer.prompt("MEID")
        model_number = model_number or typer.prompt("Model Number")

    dev = Device(
        DeviceInfoComponent(
            name=device_name,
            operating_system=operating_system,
            operating_system_version=os_version,
            operating_system_build=os_build,
            product_type=hardware_version,
            model_number=model_number,
        ),
        MachineDataComponent(
            serial_number=serial_number,
            identifier=b64encode(udid.encode()).decode() if udid else None,
            imei=imei,
            meid=meid,
        ),
        APNsCredentialsComponent(),
    )

    dev.write(CLIOptions.device_path / serial_number)

    if not dev.machine_data.requires_provisioning or skip_provisioning:
        typer.echo("Skipping Anisette provisioning.")
        return

    logger.info("Starting Anisette provisioning...")
    if dev.machine_data.requires_provisioning:
        anisette_provider = AnisetteV3Provider(dev.machine_data)
        await anisette_provider.provision()

    logger.info("Fetching push certificate from Albert...")
    if dev.apns_credentials.requires_provisioning:
        push_key, push_cert = await request_push_certificate(dev.device_info, dev.machine_data)
        dev.apns_credentials.push_key = push_key
        dev.apns_credentials.push_cert = push_cert

    logger.info("Fetching push token from APNs...")
    apns_client = APNsClientStream()
    await apns_client.connect()
    await apns_client.send(
        ConnectCommand(
            push_token=dev.apns_credentials.push_token,
            certificate=dev.apns_credentials.push_cert,
            nonce=(nonce := Nonce()),
            signature=b"\x01\x01" + dev.apns_credentials.push_key.sign(bytes(nonce), PKCS1v15(), SHA1()),  # noqa: S303
        ),
    )
    response = await apns_client.read()
    if not isinstance(response, ConnectResponseCommand):
        msg = "Invalid response from APNs server."
        raise TypeError(msg)

    if response.status != 0:
        msg = f"Failed to provision push credentials: {response.status}"
        raise ValueError(msg)

    await apns_client.close()
    dev.apns_credentials.push_token = response.push_token

    dev.write(CLIOptions.device_path / serial_number)


@app.command(help="Remove a device.")
@app.command(name="rm", hidden=True)
@app.command(name="delete", hidden=True)
@run_async
async def remove() -> None: ...


@app.command(help="Provision a device through Anisette.")
@app.command(name="prov", hidden=True)
@run_async
async def provision(
    serial_number: SerialArgument = CLIOptions.selected_device,
    *,
    skip_anisette: Annotated[
        bool,
        typer.Option(
            "--skip-anisette",
            help="Skip Anisette provisioning.",
        ),
    ] = False,
    skip_push: Annotated[
        bool,
        typer.Option(
            "--skip-push",
            help="Skip push certificate provisioning.",
        ),
    ] = False,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Force a re-provision of the device.",
        ),
    ] = False,
) -> None:
    serial_number = serial_number or CLIOptions.selected_device
    dev = fetch_device(CLIOptions.device_path, serial_number)

    if force is True:
        logger.warning(
            "Re-provisioning the Anisette data and/or push credentials may cause issues with authenticated users!",
        )

    required_provisioning = False
    if not skip_anisette and (dev.machine_data.requires_provisioning or force):
        required_provisioning = True

        anisette_provider = AnisetteV3Provider(dev.machine_data)
        await anisette_provider.provision()

    if not skip_push and (dev.apns_credentials.requires_provisioning or force):
        required_provisioning = True

        push_key, push_cert = await request_push_certificate(dev.device_info, dev.machine_data)
        dev.apns_credentials.push_key = push_key
        dev.apns_credentials.push_certificate = push_cert

        apns_client = APNsClientStream()
        await apns_client.connect()
        await apns_client.send(
            ConnectCommand(
                push_token=None,
                certificate=dev.apns_credentials.push_cert,
                nonce=(nonce := Nonce()),
                signature=b"\x01\x01" + dev.apns_credentials.push_key.sign(bytes(nonce), PKCS1v15(), SHA1()),  # noqa: S303
                os_version=dev.device_info.operating_system_version,
                os_build=dev.device_info.operating_system_build,
                hardware_version=dev.device_info.product_type,
            ),
        )

        response = await apns_client.read()
        if not isinstance(response, ConnectResponseCommand):
            msg = "Invalid response from APNs server."
            raise ValueError(msg)

        if response.status != 0:
            msg = f"Failed to provision push credentials: {response.status.name}"
            raise ValueError(msg)

        await apns_client.close()
        dev.apns_credentials.push_token = response.push_token

    if not required_provisioning:
        logger.error("Device is already provisioned. Use --force to re-provision.")
        raise typer.Abort

    dev.write(CLIOptions.device_path / serial_number)


@app.command(help="Select this device for use with other PommeKit commands.")
@app.command(name="sel", hidden=True)
def select(serial_number: SerialArgument = None) -> None:
    if serial_number is None:
        if CLIOptions.selected_device is None:
            raise typer.Exit

        typer.echo(CLIOptions.selected_device)
        raise typer.Exit

    set_selected_device(CLIOptions.device_path, serial_number)


@app.callback(no_args_is_help=True, hidden=False)
def device(
    path: Annotated[
        Path,
        typer.Option(
            "--path",
            "-p",
            envvar="POMMEKIT_DEVICE_PATH",
            help="The path to save/load device data to.",
        ),
    ] = CLIOptions.device_path,
) -> None:
    CLIOptions.device_path = path
    CLIOptions.selected_device = get_selected_device(path)

    logger.debug(f"Current device path: '{CLIOptions.device_path}'")
    logger.debug(f"Current selected device: '{CLIOptions.selected_device}'")
