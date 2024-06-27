#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel

"""Module containing the Albert activation logic."""

from __future__ import annotations

import plistlib
from importlib import resources
from logging import getLogger
from typing import TYPE_CHECKING, Final, Literal, Self, TypedDict
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_private_key
from cryptography.x509 import Certificate, load_pem_x509_certificate
from httpx import AsyncClient, Response
from lxml import etree

from ..albert.device_csr import generate_device_csr
from ..device import (
    OperatingSystem,
    ProvidesIdentifier,
    ProvidesSerialNumber,
)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    from lxml.etree import _Element

    from ..device import (
        DeviceInfoComponent,
        MachineDataComponent,
        ProvidesDeviceInfo,
        ProvidesMachineData,
    )

_RESOURCE_ROOT: Final = resources.files(__package__)
FAIRPLAY_PRIVATE_KEY = load_pem_private_key((_RESOURCE_ROOT / "fairplay.key").read_bytes(), password=None)
FAIRPLAY_CERT_CHAIN = (_RESOURCE_ROOT / "fairplay-chain.crt").read_bytes()

ACTIVATION_URL: Final = "https://albert.apple.com/deviceservices/deviceActivation?device=MacOS"
ERROR_KEY_XPATH: Final = ".//TextView[contains(text(), 'ErrorKey: ')]/SetFontStyle"
MESSAGE_KEY_XPATH: Final = ".//TextView[contains(text(), 'MessageKey: ')]/SetFontStyle"
UNBRICK_REASON_DETAIL_XPATH: Final = ".//TextView[contains(text(), 'UnbrickReasonDetail: ')]/SetFontStyle"


class AlbertError(Exception):
    """Generic exception raised when an Albert request fails."""

    def __init__(
        self: Self,
        error_key: str | None = None,
        message_key: str | None = None,
        unbrick_reason_detail: str | None = None,
    ) -> None:
        """Initialize the exception with the response text."""
        detail = ""
        if all((error_key, message_key, unbrick_reason_detail)):
            detail = f" ({error_key}: {unbrick_reason_detail}) [{message_key}]"

        msg = f"Failed to retrieve push certificate from Albert.{detail}"
        super().__init__(msg)


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
    InternationalMobileEquipmentIdentity: str | None


class ActivationInfo(TypedDict):
    """The activation info sent to Apple through Albert."""

    ActivationInfoComplete: Literal[True]
    ActivationInfoXML: bytes
    FairPlayCertChain: bytes
    FairPlaySignature: bytes


ActivationPayload = TypedDict("ActivationPayload", {"activation-info": str})


class ActivationRecord(TypedDict):
    """The activation record returned by Albert."""

    DeviceCertificate: bytes


DeviceActivation = TypedDict(
    "DeviceActivation",
    {
        "ack-received": bool,
        "activation-record": ActivationRecord,
        "show-settings": bool,
    },
)

AlbertResponseData = TypedDict(
    "AlbertResponseData",
    {
        "device-activation": DeviceActivation,
    },
)


class ProvidesSerialNumberAndIdentifier(ProvidesSerialNumber, ProvidesIdentifier):
    """Interface for components that provide both the serial number and the identifier."""


logger = getLogger(__name__)


async def request_push_certificate(
    device_info: DeviceInfoComponent | ProvidesDeviceInfo,
    machine_data: MachineDataComponent | ProvidesMachineData | ProvidesSerialNumberAndIdentifier,
    *,
    skip_randomness: bool = False,
) -> tuple[RSAPrivateKey, Certificate]:
    """
    Request a push certificate from Albert.

    :return: A `tuple` containing the private key and the push certificate.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    device_class = device_info.operating_system
    match device_class:
        case OperatingSystem.MACOS:
            device_class = "MacOS"

        case OperatingSystem.IOS:
            device_class = "iPhone"

        case OperatingSystem.WINDOWS:
            ...

        case _:
            logger.warning("Operating system for this device has not been vetted for use with Albert.")

    activation_info_content: ActivationInfoContent = {
        k: v
        for k, v in {
            "ActivationRandomness": str(uuid4()).upper() if not skip_randomness else None,
            "ActivationState": "Unactivated",
            "DeviceClass": device_class,
            "DeviceCertRequest": generate_device_csr(private_key).public_bytes(Encoding.PEM),
            "ModelNumber": device_info.model_number,
            "ProductType": device_info.product_type,
            "ProductVersion": device_info.operating_system_version,
            "BuildVersion": device_info.operating_system_build,
            "SerialNumber": machine_data.serial_number,
            "UniqueDeviceID": machine_data.identifier,
            "InternationalMobileEquipmentIdentity": machine_data.imei,
            "MobileEquipmentIdentifier": machine_data.meid,
        }.items()
        if v is not None
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
        logger.error(
            f"Failed to retrieve push certificate from Albert. {response.status_code} — {response.reason_phrase}",
        )
        raise AlbertError

    root: _Element = etree.fromstring(response.text, etree.XMLParser(recover=True, resolve_entities=False))  # noqa: S320
    response_data: AlbertResponseData = plistlib.loads(
        etree.tostring(root.find(".//plist", namespaces=root.nsmap)),
    )

    if response_data == {}:
        error_key = root.xpath(ERROR_KEY_XPATH, namespaces=root.nsmap)[0].text
        message_key = root.xpath(MESSAGE_KEY_XPATH, namespaces=root.nsmap)[0].text
        unbrick_reason_detail = root.xpath(UNBRICK_REASON_DETAIL_XPATH, namespaces=root.nsmap)[0].text.replace("\n", "")
        raise AlbertError(error_key, message_key, unbrick_reason_detail)

    certificate_data = response_data["device-activation"]["activation-record"]["DeviceCertificate"]

    device_certificate = load_pem_x509_certificate(certificate_data)

    logger.info("Successfully retrieved push certificate from Albert.")
    return private_key, device_certificate
