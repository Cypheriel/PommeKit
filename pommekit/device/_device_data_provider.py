#  Copyright (C) 2024  Cypheriel
from abc import ABC
from base64 import b64decode
from collections.abc import Callable
from dataclasses import dataclass, is_dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Protocol, TypedDict
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate

from pommekit.device import OperatingSystem

AnisetteHeaders = TypedDict("AnisetteHeaders", {
    "User-Agent": str,
    "X-Apple-I-MD-M": str,
    "X-Apple-I-MD": str,
    "X-Apple-I-MD-RINFO": str,
    "X-Apple-I-MD-LU": str,
    "X-Apple-I-SRL-NO": str,
    "X-Apple-I-Client-Time": str,
    "X-Apple-I-TimeZone": str,
    "X-Apple-Locale": str,
    "X-Mme-Client-Info": str,
    "X-Mme-Device-Id": str,
}, total=False)


@dataclass
class DeviceDataComponent(ABC):
    @classmethod
    def from_dict(cls, data: dict[str, str | None]):
        if is_dataclass(cls):
            return cls.__init__({k: (lambda: v) for k, v in data.items()})

        raise TypeError(f"{cls.__name__} is not a dataclass")


@dataclass
class DeviceInfoComponent(DeviceDataComponent):
    _name_provider: Callable[[], str | None] = lambda: None
    _operating_system_provider: Callable[[], OperatingSystem | None] = lambda: None
    _operating_system_version_provider: Callable[[], str | None] = lambda: None
    _operating_system_build_provider: Callable[[], str | None] = lambda: None
    _model_provider: Callable[[], str | None] = lambda: None

    @property
    def name(self) -> str | None:
        return self._name_provider()

    @property
    def operating_system(self) -> OperatingSystem | None:
        return self._operating_system_provider()

    @property
    def operating_system_version(self) -> str | None:
        return self._operating_system_version_provider()

    @property
    def operating_system_build(self) -> str | None:
        return self._operating_system_build_provider()

    @property
    def model(self) -> str | None:
        return self._model_provider()

    def __dict__(self):
        return {
            "name": self.name,
            "operating_system": self.operating_system,
            "operating_system_version": self.operating_system_version,
            "operating_system_build": self.operating_system_build,
            "model": self.model,
        }


@dataclass
class MachineDataComponent(DeviceDataComponent):
    _serial_number_provider: Callable[[], str | None] = lambda: None
    _identifier_provider: Callable[[], str | None] = lambda: None
    _user_agent_provider: Callable[[], str | None] = lambda: None
    _client_info_provider: Callable[[], str | None] = lambda: None
    _adi_pb_provider: Callable[[], str | None] = lambda: None
    _machine_id_provider: Callable[[], str | None] = lambda: None
    _one_time_password_provider: Callable[[], str | None] = lambda: None
    _routing_info_provider: Callable[[], str | None] = lambda: None

    @property
    def serial_number(self) -> str | None:
        return self._serial_number_provider()

    @property
    def identifier(self) -> str | None:
        return self._identifier_provider()

    @property
    def user_agent(self) -> str | None:
        return self._user_agent_provider()

    @property
    def client_info(self) -> str | None:
        return self._client_info_provider()

    @property
    def adi_pb(self) -> str | None:
        return self._adi_pb_provider()

    @property
    def machine_id(self) -> str | None:
        return self._machine_id_provider()

    @property
    def one_time_password(self) -> str | None:
        return self._one_time_password_provider()

    @property
    def routing_info(self) -> str | None:
        return self._routing_info_provider()

    @property
    def anisette_headers(self) -> AnisetteHeaders:
        decoded_uuid = b64decode(self.identifier)
        client_time = datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat()
        return {key: value for key, value in {
            "User-Agent": self.user_agent,
            "X-Apple-I-MD-M": self.machine_id,
            "X-Apple-I-MD": self.one_time_password,
            "X-Apple-I-MD-RINFO": self.routing_info,
            "X-Apple-I-MD-LU": sha256(decoded_uuid).hexdigest().upper(),
            "X-Apple-I-SRL-NO": self.serial_number or "0",
            "X-Apple-I-Client-Time": client_time.replace("+00:00", "") + "Z",
            "X-Apple-I-TimeZone": "UTC",
            "X-Apple-Locale": "en_US",
            "X-Mme-Client-Info": self.client_info,
            "X-Mme-Device-Id": str(UUID(bytes=decoded_uuid)).upper(),
        }.items() if value}

    @property
    def requires_provisioning(self) -> bool:
        return not all((
            self.serial_number,
            self.identifier,
            self.user_agent,
            self.client_info,
            self.adi_pb,
            self.machine_id,
            self.one_time_password,
            self.routing_info,
        ))

    def __dict__(self):
        return {
            "serial_number": self.serial_number,
            "identifier": self.identifier,
            "user_agent": self.user_agent,
            "client_info": self.client_info,
            "adi_pb": self.adi_pb,
            "machine_id": self.machine_id,
            "one_time_password": self.one_time_password,
            "routing_info": self.routing_info,
        }


@dataclass
class APNsCredentialsComponent(DeviceDataComponent):
    _push_token_provider: Callable[[], str | None] = lambda: None
    _push_key_provider: Callable[[], RSAPrivateKey | None] = lambda: None
    _push_cert_provider: Callable[[], Certificate | None] = lambda: None

    @property
    def push_token(self) -> str | None:
        return self._push_token_provider()

    @property
    def push_key(self) -> RSAPrivateKey | None:
        return self._push_key_provider()

    @property
    def push_cert(self) -> Certificate | None:
        return self._push_cert_provider()


class ProvidesDeviceInfo(Protocol):
    @property
    def name(self) -> str | None:
        ...

    @property
    def operating_system(self) -> OperatingSystem | None:
        ...

    @property
    def operating_system_version(self) -> str | None:
        ...

    @property
    def operating_system_build(self) -> str | None:
        ...

    @property
    def model(self) -> str | None:
        ...


class ProvidesSerialNumber(Protocol):
    @property
    def serial_number(self) -> str | None:
        ...


class ProvidesIdentifier(Protocol):
    @property
    def identifier(self) -> str | None:
        ...


class ProvidesMachineData(Protocol, ProvidesSerialNumber):
    @property
    def identifier(self) -> str | None:
        ...

    @property
    def user_agent(self) -> str | None:
        ...

    @property
    def client_info(self) -> str | None:
        ...

    @property
    def adi_pb(self) -> str | None:
        ...

    @property
    def machine_id(self) -> str | None:
        ...

    @property
    def one_time_password(self) -> str | None:
        ...

    @property
    def routing_info(self) -> str | None:
        ...


class ProvidesAnisetteHeaders(Protocol):
    @property
    def anisette_headers(self) -> AnisetteHeaders:
        ...


class ProvidesPushKeypair(Protocol):
    @property
    def push_key(self) -> RSAPrivateKey | None:
        ...

    @property
    def push_cert(self) -> Certificate | None:
        ...
