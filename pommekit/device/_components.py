#  Copyright (C) 2024  Cypheriel
from abc import ABC, abstractmethod
from base64 import b64decode
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from logging import getLogger
from typing import NoReturn, Protocol, Self, TypedDict, TypeVar
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate

from ._operating_system import OperatingSystem

logger = getLogger(__name__)

AnisetteHeaders = TypedDict(
    "AnisetteHeaders",
    {
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
    },
    total=False,
)

_T = TypeVar("_T")


def _unwrap_provider(provider: Callable[[], _T] | _T) -> _T:
    return provider() if callable(provider) else provider


@dataclass
class DeviceDataComponent(ABC):
    @property
    def missing(self: Self) -> dict[str, ...]:
        return {k: v for k, v in self.as_dict().items() if v is None}

    @classmethod
    @abstractmethod
    def from_dict(cls: type[Self], data: dict[str, str | None]) -> Self: ...

    @abstractmethod
    def as_dict(self: Self) -> dict[str, ...]: ...


#
# -- Device Info Providers --
#
# These protocols are used to provide device information to various receivers.
# Device information is mostly superficial and used for identification purposes.
#


class DeviceInfoComponent(DeviceDataComponent):
    @property
    def name(self: Self) -> str | None:
        return _unwrap_provider(self._name_provider)

    @name.setter
    def name(self: Self, value: str) -> None:
        self._name_provider = value

    @property
    def operating_system(self: Self) -> OperatingSystem | None:
        return _unwrap_provider(self._operating_system_provider)

    @operating_system.setter
    def operating_system(self: Self, value: OperatingSystem) -> None:
        self._operating_system_provider = value

    @property
    def operating_system_version(self: Self) -> str | None:
        return _unwrap_provider(self._operating_system_version_provider)

    @operating_system_version.setter
    def operating_system_version(self: Self, value: str) -> None:
        self._operating_system_version_provider = value

    @property
    def operating_system_build(self: Self) -> str | None:
        return _unwrap_provider(self._operating_system_build_provider)

    @operating_system_build.setter
    def operating_system_build(self: Self, value: str) -> None:
        self._operating_system_build_provider = value

    @property
    def product_type(self: Self) -> str | None:
        return _unwrap_provider(self._product_type_provider)

    @product_type.setter
    def product_type(self: Self, value: str) -> None:
        self._product_type_provider = value

    @property
    def model_number(self: Self) -> str | None:
        return _unwrap_provider(self._model_number_provider)

    @model_number.setter
    def model_number(self: Self, value: str) -> None:
        self._model_number_provider = value

    def __init__(
        self: Self,
        *,
        name: Callable[[], str | None] | str | None = None,
        operating_system: Callable[[], OperatingSystem | None] | OperatingSystem | None = None,
        operating_system_version: Callable[[], str | None] | str | None = None,
        operating_system_build: Callable[[], str | None] | str | None = None,
        product_type: Callable[[], str | None] | str | None = None,
        model_number: Callable[[], str | None] | str | None = None,
    ) -> None:
        self._name_provider = name
        self._operating_system_provider = operating_system
        self._operating_system_version_provider = operating_system_version
        self._operating_system_build_provider = operating_system_build
        self._product_type_provider = product_type
        self._model_number_provider = model_number

    def as_dict(self: Self) -> dict[str, str]:
        return {
            "name": self.name,
            "operating_system": self.operating_system,
            "operating_system_version": self.operating_system_version,
            "operating_system_build": self.operating_system_build,
            "model_number": self.model_number,
            "product_type": self.product_type,
        }

    @classmethod
    def from_dict(cls: type[Self], data: dict[str, str | None]) -> Self:
        return cls(
            name=data.get("name"),
            operating_system=data.get("operating_system"),
            operating_system_version=data.get("operating_system_version"),
            operating_system_build=data.get("operating_system_build"),
            model_number=data.get("model_number"),
            product_type=data.get("product_type"),
        )


class ProvidesName(Protocol):
    @property
    def name(self: Self) -> str | None: ...


class ProvidesOperatingSystem(Protocol):
    @property
    def operating_system(self: Self) -> OperatingSystem | None: ...


class ProvidesOperatingSystemVersion(Protocol):
    @property
    def operating_system_version(self: Self) -> str | None: ...


class ProvidesOperatingSystemBuild(Protocol):
    @property
    def operating_system_build(self: Self) -> str | None: ...


class ProvidesProductType(Protocol):
    @property
    def product_type(self: Self) -> str | None: ...


class ProvidesModelNumber(Protocol):
    @property
    def model_number(self: Self) -> str | None: ...


class ProvidesDeviceInfo(
    ProvidesName,
    ProvidesOperatingSystem,
    ProvidesOperatingSystemVersion,
    ProvidesOperatingSystemBuild,
    ProvidesProductType,
    ProvidesModelNumber,
): ...


#
# -- Machine Data Providers --
#
# These protocols are used to provide machine data to various receivers.
# The machine data is used to identify the device and used to generate the Anisette headers
#


class MachineDataComponent(DeviceDataComponent):
    @property
    def serial_number(self: Self) -> str | None:
        return _unwrap_provider(self._serial_number_provider)

    @serial_number.setter
    def serial_number(self: Self, value: str | None) -> None:
        self._serial_number_provider = value

    @property
    def imei(self: Self) -> str | None:
        return _unwrap_provider(self._imei_provider)

    @imei.setter
    def imei(self: Self, value: str | None) -> None:
        self._imei_provider = value

    @property
    def meid(self: Self) -> str | None:
        return _unwrap_provider(self._meid_provider)

    @meid.setter
    def meid(self: Self, value: str | None) -> None:
        self._meid_provider = value

    @property
    def identifier(self: Self) -> str | None:
        return _unwrap_provider(self._identifier_provider)

    @identifier.setter
    def identifier(self: Self, value: str | None) -> None:
        self._identifier_provider = value

    @property
    def user_agent(self: Self) -> str | None:
        return _unwrap_provider(self._user_agent_provider)

    @user_agent.setter
    def user_agent(self: Self, value: str | None) -> None:
        self._user_agent_provider = value

    @property
    def client_info(self: Self) -> str | None:
        return _unwrap_provider(self._client_info_provider)

    @client_info.setter
    def client_info(self: Self, value: str | None) -> None:
        self._client_info_provider = value

    @property
    def adi_pb(self: Self) -> str | None:
        return _unwrap_provider(self._adi_pb_provider)

    @adi_pb.setter
    def adi_pb(self: Self, value: str | None) -> None:
        self._adi_pb_provider = value

    @property
    def machine_id(self: Self) -> str | None:
        return _unwrap_provider(self._machine_id_provider)

    @machine_id.setter
    def machine_id(self: Self, value: str | None) -> None:
        self._machine_id_provider = value

    @property
    def one_time_password(self: Self) -> str | None:
        return _unwrap_provider(self._one_time_password_provider)

    @one_time_password.setter
    def one_time_password(self: Self, value: str | None) -> None:
        self._one_time_password_provider = value

    @property
    def routing_info(self: Self) -> str | None:
        return _unwrap_provider(self._routing_info_provider)

    @routing_info.setter
    def routing_info(self: Self, value: str | None) -> None:
        self._routing_info_provider = value

    @property
    def anisette_headers(self: Self) -> AnisetteHeaders:
        decoded_uuid = b64decode(self.identifier)
        client_time = datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat()
        return {
            key: value
            for key, value in {
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
            }.items()
            if value
        }

    @property
    def requires_provisioning(self: Self) -> bool:
        return set(self.missing.keys()) != {"imei", "meid"}

    def __init__(
        self: Self,
        *,
        serial_number: Callable[[], str | None] | str | None = None,
        imei: Callable[[], str | None] | str | None = None,
        meid: Callable[[], str | None] | str | None = None,
        identifier: Callable[[], str | None] | str | None = None,
        user_agent: Callable[[], str | None] | str | None = None,
        client_info: Callable[[], str | None] | str | None = None,
        adi_pb: Callable[[], str | None] | str | None = None,
        machine_id: Callable[[], str | None] | str | None = None,
        one_time_password: Callable[[], str | None] | str | None = None,
        routing_info: Callable[[], str | None] | str | None = None,
    ) -> None:
        self._serial_number_provider = serial_number
        self._imei_provider = imei
        self._meid_provider = meid
        self._identifier_provider = identifier
        self._user_agent_provider = user_agent
        self._client_info_provider = client_info
        self._adi_pb_provider = adi_pb
        self._machine_id_provider = machine_id
        self._one_time_password_provider = one_time_password
        self._routing_info_provider = routing_info

    def as_dict(self: Self) -> dict[str, str]:
        return {
            "serial_number": self.serial_number,
            "identifier": self.identifier,
            "imei": self.imei,
            "meid": self.meid,
            "user_agent": self.user_agent,
            "client_info": self.client_info,
            "adi_pb": self.adi_pb,
            "machine_id": self.machine_id,
            "one_time_password": self.one_time_password,
            "routing_info": self.routing_info,
        }

    @classmethod
    def from_dict(cls: type[Self], data: dict[str, str | None]) -> Self:
        return cls(
            serial_number=data.get("serial_number"),
            identifier=data.get("identifier"),
            imei=data.get("imei"),
            meid=data.get("meid"),
            user_agent=data.get("user_agent"),
            client_info=data.get("client_info"),
            adi_pb=data.get("adi_pb"),
            machine_id=data.get("machine_id"),
            one_time_password=data.get("one_time_password"),
            routing_info=data.get("routing_info"),
        )


class ProvidesSerialNumber(Protocol):
    @property
    def serial_number(self: Self) -> str | None: ...


class ProvidesIMEI(Protocol):
    @property
    def imei(self: Self) -> str | None: ...


class ProvidesMEID(Protocol):
    @property
    def meid(self: Self) -> str | None: ...


class ProvidesIdentifier(Protocol):
    @property
    def identifier(self: Self) -> str | None: ...


class ProvidesUserAgent(Protocol):
    @property
    def user_agent(self: Self) -> str | None: ...


class ProvidesClientInfo(Protocol):
    @property
    def client_info(self: Self) -> str | None: ...


class ProvidesADIPB(Protocol):
    @property
    def adi_pb(self: Self) -> str | None: ...


class ProvidesMachineID(Protocol):
    @property
    def machine_id(self: Self) -> str | None: ...


class ProvidesOneTimePassword(Protocol):
    @property
    def one_time_password(self: Self) -> str | None: ...


class ProvidesRoutingInfo(Protocol):
    @property
    def routing_info(self: Self) -> str | None: ...


class ProvidesMachineData(
    ProvidesSerialNumber,
    ProvidesIMEI,
    ProvidesMEID,
    ProvidesIdentifier,
    ProvidesUserAgent,
    ProvidesClientInfo,
    ProvidesADIPB,
    ProvidesMachineID,
    ProvidesOneTimePassword,
    ProvidesRoutingInfo,
): ...


class ProvidesAnisetteHeaders(Protocol):
    @property
    def anisette_headers(self: Self) -> AnisetteHeaders: ...


#
# -- APNs Credential Providers --
#
# The protocols are used to provide APNs credentials.
# The APNs credentials are used to authenticate with the APNs server, as well as some IDS functions.
#


class ProvidesPushToken(Protocol):
    @property
    def push_token(self: Self) -> str | None: ...


class ProvidesPushKeypair(Protocol):
    @property
    def push_key(self: Self) -> RSAPrivateKey | None: ...

    @property
    def push_cert(self: Self) -> Certificate | None: ...


class APNsCredentialsComponent(DeviceDataComponent):
    @property
    def push_token(self: Self) -> str | None:
        return _unwrap_provider(self._push_token_provider)

    @push_token.setter
    def push_token(self: Self, value: str | None) -> None:
        self._push_token_provider = value

    @property
    def push_key(self: Self) -> RSAPrivateKey | None:
        return _unwrap_provider(self._push_key_provider)

    @push_key.setter
    def push_key(self: Self, value: RSAPrivateKey | None) -> None:
        self._push_key_provider = value

    @property
    def push_cert(self: Self) -> Certificate | None:
        return _unwrap_provider(self._push_cert_provider)

    @push_cert.setter
    def push_cert(self: Self, value: Certificate | None) -> None:
        self._push_cert_provider = value

    @property
    def requires_provisioning(self: Self) -> bool:
        return not all((self.push_token, self.push_key, self.push_cert))

    def __init__(
        self: Self,
        *,
        push_token: Callable[[], str | None] | str | None = None,
        push_key: Callable[[], RSAPrivateKey | None] | RSAPrivateKey | None = None,
        push_cert: Callable[[], Certificate | None] | Certificate | None = None,
    ) -> None:
        self._push_token_provider = push_token
        self._push_key_provider = push_key
        self._push_cert_provider = push_cert

    def as_dict(self: Self) -> dict[str, str]:
        return {
            "push_token": self.push_token,
            "push_key": self.push_key,
            "push_cert": self.push_cert,
        }

    @classmethod
    def from_dict(cls: type[Self], _data: dict[str, str | None]) -> NoReturn:
        msg = "APNsCredentialsComponent cannot be created from a dictionary."
        raise NotImplementedError(msg)


class NoneProvider:
    def __getattr__(self: Self, _: ...) -> None:
        return None
