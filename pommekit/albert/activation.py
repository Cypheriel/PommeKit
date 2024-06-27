#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel

"""Module containing the Albert activation logic."""

from __future__ import annotations

import plistlib
import re
from base64 import b64decode
from importlib import resources
from logging import getLogger
from typing import TYPE_CHECKING, Final, Literal, TypedDict
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_private_key
from cryptography.x509 import Certificate, load_pem_x509_certificate
from httpx import AsyncClient, Response

from ..albert.device_csr import generate_device_csr

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

    from ..device import DeviceInfoComponent, MachineDataComponent, ProvidesDeviceInfo, ProvidesMachineData

_RESOURCE_ROOT: Final = resources.files(__package__)
FAIRPLAY_PRIVATE_KEY = load_pem_private_key((_RESOURCE_ROOT / "fairplay.key").read_bytes(), password=None)
FAIRPLAY_CERT_CHAIN = (_RESOURCE_ROOT / "fairplay-chain.crt").read_bytes()

ACTIVATION_URL: Final = "https://albert.apple.com/deviceservices/deviceActivation?device=MacOS"
CERTIFICATE_RESPONSE_PATTERN: Final = re.compile(r"<Protocol>(.*)</Protocol>")


class AlbertError(BaseException):
    """Generic exception raised when an Albert request fails."""

    def __init__(self, response_text: str) -> None:
        """Initialize the exception with the response text."""
        super().__init__(f"Failed to retrieve push certificate from Albert. {response_text = }")


class ActivationInfoContent(TypedDict):
    """The content of the activation info."""

    ActivationRandomness: str
    ActivationState: Literal["Unactivated"]
    DeviceCertRequest: bytes
    DeviceClass: Literal["MacOS", "Windows"]
    ProductType: str | None
    ProductVersion: str | None
    BuildVersion: str | None
    SerialNumber: str | None
    UniqueDeviceID: str


class ActivationInfo(TypedDict):
    """The activation info sent to Apple through Albert."""

    ActivationInfoComplete: Literal[True]
    ActivationInfoXML: bytes
    FairPlayCertChain: bytes
    FairPlaySignature: bytes


ActivationPayload = TypedDict("ActivationPayload", {"activation-info": str})

logger = getLogger(__name__)


async def request_push_certificate(
    device_info: DeviceInfoComponent | ProvidesDeviceInfo,
    machine_data: MachineDataComponent | ProvidesMachineData,
) -> tuple[RSAPrivateKey, Certificate]:
    """
    Request a push certificate from Albert.

    :return: A `tuple` containing the private key and the push certificate.
    """
    if (product_type := device_info.model) is None:
        msg = "Device product_type is required for activation."
        raise ValueError(msg)

    if (operating_system_version := device_info.operating_system_version) is None:
        msg = "Device operating system version is required for activation."
        raise ValueError(msg)

    if (operating_system_build := device_info.operating_system_build) is None:
        msg = "Device operating system build is required for activation."
        raise ValueError(msg)

    if (serial_number := machine_data.serial_number) is None:
        msg = "Device serial number is required for activation."
        raise ValueError(msg)

    if (identifier := machine_data.identifier) is None:
        msg = "Device identifier is required for activation."
        raise ValueError(msg)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    activation_info_content: ActivationInfoContent = {
        "ActivationRandomness": str(uuid4()).upper(),
        "ActivationState": "Unactivated",
        "DeviceClass": "MacOS",  # NOTE: Other DeviceClass values are currently unknown and undocumented.
        "DeviceCertRequest": generate_device_csr(private_key).public_bytes(Encoding.PEM),
        "ProductType": product_type,
        "ProductVersion": operating_system_version,
        "BuildVersion": operating_system_build,
        "SerialNumber": serial_number,
        "UniqueDeviceID": str(UUID(bytes=b64decode(identifier))).upper(),
    }

    activation_info_xml = plistlib.dumps(activation_info_content)
    activation_signature = FAIRPLAY_PRIVATE_KEY.sign(activation_info_xml, PKCS1v15(), SHA1())  # noqa: S303

    activation_info: ActivationInfo = {
        "ActivationInfoComplete": True,
        "ActivationInfoXML": activation_info_xml,
        "FairPlayCertChain": FAIRPLAY_CERT_CHAIN,
        "FairPlaySignature": activation_signature,
    }

    payload: ActivationPayload = {"activation-info": plistlib.dumps(activation_info).decode()}

    async with AsyncClient() as client:
        response: Response = await client.post(
            ACTIVATION_URL,
            data=payload,
        )

    if response.is_error:
        raise AlbertError(response.text)

    if (match := CERTIFICATE_RESPONSE_PATTERN.search(response.text)) is None:
        raise AlbertError(response.text)

    protocol_data = plistlib.loads(match.group(1).encode())
    certificate_data = protocol_data["device-activation"]["activation-record"]["DeviceCertificate"]

    device_certificate = load_pem_x509_certificate(certificate_data)
    return private_key, device_certificate
