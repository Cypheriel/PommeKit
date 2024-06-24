#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel

"""Module containing the Albert activation logic."""

from __future__ import annotations

import plistlib
import re
from importlib import resources
from logging import getLogger
from typing import TYPE_CHECKING, Final, Literal, TypedDict

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_private_key
from cryptography.x509 import Certificate, load_pem_x509_certificate
from httpx import AsyncClient, Response

from ..albert.device_csr import generate_device_csr

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

_RESOURCE_ROOT: Final = resources.files(__package__)
FAIRPLAY_PRIVATE_KEY = load_pem_private_key((_RESOURCE_ROOT / "fairplay.key").read_bytes(), password=None)
FAIRPLAY_CERT_CHAIN = (_RESOURCE_ROOT / "fairplay-chain.crt").read_bytes()

ACTIVATION_URL: Final = "https://albert.apple.com/deviceservices/deviceActivation?device=MacOS"
CERTIFICATE_RESPONSE_PATTERN: Final = re.compile(r"<Protocol>(.*)</Protocol>")


class ActivationInfoContent(TypedDict):
    """The content of the activation info."""

    ActivationRandomness: str
    ActivationState: Literal["Unactivated"]
    DeviceCertRequest: bytes
    DeviceClass: Literal["MacOS", "Windows"]
    ProductType: str
    ProductVersion: str
    BuildVersion: str
    SerialNumber: str
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
    private_key: RSAPrivateKey | None = None,
    activation_info_content: ActivationInfoContent | None = None,
    fairplay_private_key: RSAPrivateKey = FAIRPLAY_PRIVATE_KEY,
    fairplay_cert_chain: bytes = FAIRPLAY_CERT_CHAIN,
    http_client: AsyncClient | None = None,
) -> tuple[RSAPrivateKey, Certificate]:
    """
    Request a push certificate from Albert.

    :param private_key:
    :param activation_info_content: The activation info content to send to Albert.
    :param fairplay_cert_chain: Optional FairPlay certificate chain override.
    :param fairplay_private_key: Optional FairPlay private key override.
    :param http_client: The optional async HTTP _client to use for the request.
    :return: A `tuple` containing the private key and the push certificate.
    """
    if private_key is None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    if "DeviceCertRequest" not in activation_info_content:
        activation_info_content["DeviceCertRequest"] = generate_device_csr(private_key).public_bytes(Encoding.PEM)

    activation_info_xml = plistlib.dumps(activation_info_content)
    activation_signature = fairplay_private_key.sign(activation_info_xml, PKCS1v15(), SHA1())  # noqa: S303

    activation_info: ActivationInfo = {
        "ActivationInfoComplete": True,
        "ActivationInfoXML": activation_info_xml,
        "FairPlayCertChain": fairplay_cert_chain,
        "FairPlaySignature": activation_signature,
    }

    payload: ActivationPayload = {"activation-info": plistlib.dumps(activation_info).decode()}

    match http_client:
        case AsyncClient() | None:
            async with http_client or AsyncClient() as client:
                response: Response = await client.post(
                    ACTIVATION_URL,
                    data=payload,
                )
        case _:
            msg = "Unsupported HTTP _client provided."
            raise ValueError(msg)

    if not response.is_success:
        msg = f"Received non-OK status code: {response.status_code}"
        raise RuntimeError(msg)

    if (match := CERTIFICATE_RESPONSE_PATTERN.search(response.text)) is None:
        logger.debug(f"Failed to extract certificate from response: {response.text}")
        msg = "Failed to extract certificate from response."
        raise RuntimeError(msg)

    protocol_data = plistlib.loads(match.group(1).encode())
    certificate_data = protocol_data["device-activation"]["activation-record"]["DeviceCertificate"]

    device_certificate = load_pem_x509_certificate(certificate_data)
    return private_key, device_certificate
