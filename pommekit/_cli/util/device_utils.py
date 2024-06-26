#  Copyright (C) 2024  Cypheriel
from pathlib import Path

from pommekit._cli.util.app_dirs import USER_DATA_DIR
from pommekit.device import Device


def fetch_device(path: Path, serial_number: str) -> Device | None:
    if not path and not serial_number:
        msg = "Either a path or serial number must be provided."
        raise ValueError(msg)

    path = path / serial_number or USER_DATA_DIR / "Devices" / serial_number
    if not path.is_dir():
        return None

    return Device.load(path)
