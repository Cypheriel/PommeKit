#  Copyright (C) 2024  Cypheriel
from pathlib import Path


def get_selected_device(path: Path) -> str | None:
    selected_file = path / ".selected_device"

    if selected_file.is_file() and (selected_device := selected_file.read_text()):
        return selected_device
    return None


def set_selected_device(path: Path, serial: str) -> None:
    devices_dir = path
    if devices_dir.is_dir() and serial in (device.name for device in devices_dir.iterdir()):
        selected_file = path / ".selected_device"
        selected_file.write_text(serial)

    else:
        msg = "Failed to select device. Device not found."
        raise ValueError(msg)
