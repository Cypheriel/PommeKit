#  Copyright (C) 2024  Cypheriel
import json
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate

from ._device_data_provider import APNsCredentialsComponent, DeviceInfoComponent, MachineDataComponent


@dataclass
class SimulatedDevice:
    device_info: DeviceInfoComponent = field(default_factory=DeviceInfoComponent)
    machine_data: MachineDataComponent = field(default_factory=MachineDataComponent)
    apns_credentials: APNsCredentialsComponent = field(default_factory=APNsCredentialsComponent)

    def read(self, path: Path):
        if (device_info_path := path / "device_info.json").exists():
            self.device_info = DeviceInfoComponent.from_dict(json.loads(device_info_path.read_text()))

        if (machine_data_path := path / "machine_data.json").exists():
            self.machine_data = MachineDataComponent.from_dict(json.loads(machine_data_path.read_text()))

        if (push_key_path := path / "push.key").exists() and (push_cert_path := path / "push.crt").exists():
            push_key = load_pem_private_key(push_key_path.read_bytes(), password=None)
            push_cert = load_pem_x509_certificate(push_cert_path.read_bytes())
            self.apns_credentials = APNsCredentialsComponent(
                _push_key_provider=lambda: push_key,
                _push_cert_provider=lambda: push_cert,
            )

        if (push_token_path := path / "push_token.txt").exists():
            push_token = push_token_path.read_text()
            self.apns_credentials._push_key_provider = lambda: push_token

    def write(self, path: Path):
        if len(device_info := self.device_info.__dict__()) > 0:
            (path / "device_info.json").write_text(json.dumps(device_info, indent=4))

        if len(machine_data := self.machine_data.__dict__()) > 0:
            (path / "machine_data.json").write_text(json.dumps(machine_data, indent=4))

        if self.apns_credentials.push_key and self.apns_credentials.push_cert:
            (path / "push.key").write_bytes(
                self.apns_credentials.push_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL,
                                                             NoEncryption()))
            (path / "push.crt").write_bytes(self.apns_credentials.push_cert.public_bytes(Encoding.PEM))

        if self.apns_credentials.push_token:
            (path / "push_token.txt").write_text(self.apns_credentials.push_token)
