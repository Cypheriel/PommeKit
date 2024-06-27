#  Copyright (C) 2024  Cypheriel
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate

from ._components import APNsCredentialsComponent, DeviceInfoComponent, MachineDataComponent


@dataclass
class SimulatedDevice:
    device_info: DeviceInfoComponent
    machine_data: MachineDataComponent
    apns_credentials: APNsCredentialsComponent

    @classmethod
    def read(cls: type[Self], path: Path) -> Self:
        device_info = DeviceInfoComponent()
        if (device_info_path := path / "device_info.json").exists():
            device_info = DeviceInfoComponent.from_dict(json.loads(device_info_path.read_text()))

        machine_data = MachineDataComponent()
        if (machine_data_path := path / "machine_data.json").exists():
            machine_data = MachineDataComponent.from_dict(json.loads(machine_data_path.read_text()))

        apns_credentials = APNsCredentialsComponent()
        if (push_key_path := path / "push.key").exists() and (push_cert_path := path / "push.crt").exists():
            push_key = load_pem_private_key(push_key_path.read_bytes(), password=None)
            push_cert = load_pem_x509_certificate(push_cert_path.read_bytes())
            apns_credentials.push_key = push_key
            apns_credentials.push_cert = push_cert

        if (push_token_path := path / "push_token.txt").exists():
            push_token = push_token_path.read_text()
            apns_credentials.push_token = push_token

        return cls(device_info, machine_data, apns_credentials)

    def write(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)

        if len(device_info := self.device_info.as_dict()) > 0:
            (path / "device_info.json").write_text(json.dumps(device_info, indent=4))

        if len(machine_data := self.machine_data.as_dict()) > 0:
            (path / "machine_data.json").write_text(json.dumps(machine_data, indent=4))

        if self.apns_credentials.push_key and self.apns_credentials.push_cert:
            (path / "push.key").write_bytes(
                self.apns_credentials.push_key.private_bytes(
                    Encoding.PEM,
                    PrivateFormat.TraditionalOpenSSL,
                    NoEncryption(),
                ),
            )
            (path / "push.crt").write_bytes(self.apns_credentials.push_cert.public_bytes(Encoding.PEM))

        if self.apns_credentials.push_token:
            (path / "push_token.txt").write_text(self.apns_credentials.push_token)
