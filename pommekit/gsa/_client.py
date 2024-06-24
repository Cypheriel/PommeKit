#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel

from __future__ import annotations

import hmac
import logging
import plistlib
from base64 import b64encode
from dataclasses import dataclass
from enum import StrEnum
from hashlib import pbkdf2_hmac, sha256
from typing import TYPE_CHECKING, Final, Self

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.padding import PKCS7
from httpx import AsyncClient

from ..gsa._srp import SRPUser
from ._exceptions import GrandSlamError

if TYPE_CHECKING:
    from collections.abc import Callable

GSA_BASE_URL: Final = "https://gsa.apple.com"
GSA_SERVICE_URL: Final = f"{GSA_BASE_URL}/grandslam/GsService2"
GSA_TRUSTED_DEVICE_URL: Final = f"{GSA_BASE_URL}/auth/verify/trusteddevice"
GSA_VALIDATE_2FA_URL: Final = f"{GSA_SERVICE_URL}/validate"

APPLE_PLIST_HEADER: Final = (
    b"<?xml version='1.0' encoding='UTF-8'?>\n"
    b"<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'https://www.apple.com/DTDs/PropertyList-1.0.dtd'>"
)

APPLE_REJECT_DEVICE_ERROR: Final = -22421

logger = logging.getLogger(__name__)


@dataclass
class GSAResponseStatus:
    status_code: int
    status_message: str | None

    @property
    def is_success(self: Self) -> bool:
        return self.status_code == 0


def _response_status(response: dict[str, ...]) -> GSAResponseStatus:
    status = response.get("Status", response)
    status_code = status["ec"]

    return GSAResponseStatus(status_code, status.get("em"))


def _verify_headers(headers: dict[str, str]) -> bool:
    logger.debug(f"Verifying headers: {headers}")
    expected_headers = {
        h.lower()
        for h in (
            "User-Agent",
            "X-Apple-I-MD",
            "X-Apple-I-MD-RINFO",
            "X-Apple-I-MD-LU",
            "X-Apple-I-MD-M",
            # "X-Apple-I-SRL-NO",
            "X-Apple-I-Client-Time",
            "X-Apple-I-TimeZone",
            "X-Apple-Locale",
            "X-Mme-Client-Info",
            "X-Mme-Device-Id",
        )
    }

    missing_headers = expected_headers - {h.lower() for h in headers}
    if missing_headers:
        logger.warning(f"Missing headers: {missing_headers}")

    return len(missing_headers) == 0


class AUStatus(StrEnum):
    UNKNOWN = "UNKNOWN"
    TRUSTED_DEVICE = "trustedDeviceSecondaryAuth"
    SMS = "secondaryAuth"
    COMPLETE = "COMPLETE"
    NOT_STARTED = "NOT_STARTED"

    @classmethod
    def _missing_(cls: type[Self], _value: str) -> AUStatus:
        return cls.UNKNOWN


class GSAClient:
    def __init__(self: Self, anisette_provider: Callable[[], dict[str, str]]) -> None:
        """Initialize a new instance of the GSAClient class."""
        self.pet_token: str | bytes | None = None
        self.au_status: AUStatus = AUStatus.NOT_STARTED

        self._client = AsyncClient(
            verify=False,  # noqa: S501
        )
        self._anisette_provider = anisette_provider

        self._apple_id: str | None = None
        self._srp_user: SRPUser | None = None

        self._identity_token: str | None = None
        self._extra_headers: dict[str, str] = {}

    async def _request(self: Self, data: dict[str, ...]) -> dict[str, ...]:
        """Send a privileged request to the GrandSlam service."""
        headers = self._anisette_provider()
        if _verify_headers(headers) is False:
            msg = "Invalid Anisette headers."
            raise ValueError(msg)

        payload = {
            "Header": {"Version": "1.0.1"},
            "Request": {"cpd": headers} | data,
        }

        response = await self._client.post(GSA_SERVICE_URL, content=plistlib.dumps(payload), headers=headers)
        if not response.is_success:
            msg = f"Failed to authenticate with GrandSlam: {response}"
            raise GrandSlamError(msg)

        response_data = plistlib.loads(response.content)["Response"]

        status = _response_status(response_data)

        if status.status_code == APPLE_REJECT_DEVICE_ERROR:
            msg = "Apple rejected machine data. Please re-provision this device."
            raise GrandSlamError(msg, error_code=status.status_code, error_message=status.status_message)

        if status.is_success is False:
            logger.debug(f"{response_data = }")
            msg = "Unexpected error occurred!"
            raise GrandSlamError(msg, error_code=status.status_code, error_message=status.status_message)

        return response_data

    def _get_session_key(self: Self, name: str) -> bytes:
        """Generate a session key using the SRP session key."""
        return hmac.new(self._srp_user.session_key, name.encode(), sha256).digest()

    def _decrypt_cbc(self: Self, cbc_data: bytes) -> bytes:
        """Decrypt the CBC data using session keys."""
        extra_data_key = self._get_session_key("extra data key:")
        extra_data_iv = self._get_session_key("extra data iv:")[:16]

        cipher = Cipher(AES(extra_data_key), CBC(extra_data_iv))

        decryptor = cipher.decryptor()
        data = decryptor.update(cbc_data) + decryptor.finalize()

        unpadder = PKCS7(128).unpadder()
        return unpadder.update(data) + unpadder.finalize()

    async def request_device_2fa(self: Self) -> None:
        """Request a trusted device 2FA code from Apple."""
        self._extra_headers = {
            "User-Agent": "Xcode",
            "Accept": "text/x-xml-plist",
            "X-Apple-Identity-Token": self._identity_token,
        }

        response = await self._client.get(
            GSA_TRUSTED_DEVICE_URL,
            headers=self._anisette_provider() | self._extra_headers,
        )

        logger.debug(f"{response.request.headers = }")

        if not response.is_success:
            logger.debug(f"{response.content = }")
            msg = "Failed to request trusted device 2FA."
            raise GrandSlamError(
                msg,
                error_code=response.status_code,
                error_message=response.text,
            )

    async def validate_device_2fa(self: Self, security_code: str) -> bool:
        """Validate the trusted device 2FA code with Apple."""
        self._extra_headers["security-code"] = security_code
        anisette_headers = self._anisette_provider()
        _verify_headers(anisette_headers | self._extra_headers)

        response = await self._client.get(GSA_VALIDATE_2FA_URL, headers=anisette_headers | self._extra_headers)
        logger.debug(f"{response.http_version} {response.status_code} {response.reason_phrase}")
        logger.debug("\n".join(f"{k}: {v}" for k, v in response.headers.items()))
        logger.debug(f"{response.content = }")

        response_data = plistlib.loads(response.content)

        status = _response_status(response_data)

        if status.is_success is False:
            logger.error(f"Failed to validate trusted device ({status.status_code}: {status.status_message})")

        return status.is_success

    async def authenticate(self: Self, apple_id: str, password: str) -> None:
        """Authenticate with GrandSlam using the provided Apple ID and password."""
        self._apple_id = apple_id
        self._srp_user = SRPUser(self._apple_id)

        payload = {
            "A2k": self._srp_user.public_ephemeral,
            "ps": ["s2k", "s2k_fo"],
            "u": self._apple_id,
            "o": "init",
        }

        logger.info("Starting authentication with GrandSlam.")
        logger.debug(f"{payload = }")

        init_response = await self._request(payload)

        logger.debug(f"{init_response = }")

        password_hmac = pbkdf2_hmac(
            "sha256",
            sha256(password.encode()).digest(),
            init_response["s"],
            init_response["i"],
        )[:32]

        complete_response = await self._request(
            {
                "c": init_response["c"],
                "M1": self._srp_user.process_challenge(password_hmac, init_response["s"], init_response["B"]),
                "u": self._apple_id,
                "o": "complete",
            },
        )

        logger.debug("Sending confirmation response with proof to GrandSlam.")
        logger.debug(f"{complete_response = }")

        if not self._srp_user.verify_session(complete_response["M2"]):
            logger.debug(f"{complete_response = }")
            msg = "Failed to verify user SRP session."
            raise GrandSlamError(msg)

        spd_data = self._decrypt_cbc(complete_response["spd"])
        spd = plistlib.loads(APPLE_PLIST_HEADER + spd_data)

        au = complete_response.get("Status", {}).get("au")
        self.au_status = AUStatus.COMPLETE if au is None else AUStatus(au)

        match self.au_status:
            case AUStatus.TRUSTED_DEVICE:
                logger.warning("Trusted device secondary authentication required.")
            case AUStatus.SMS:
                logger.warning("Secondary authentication required.")
            case AUStatus.UNKNOWN:
                logger.warning("Unknown authentication status.")
            case AUStatus.COMPLETE:
                logger.info("Authentication complete.")

        self.pet_token = spd.get("t", {}).get("com.apple.gs.idms.pet", {}).get("token", None)
        self._identity_token = b64encode(f"{spd['adsid']}:{spd['GsIdmsToken']}".encode()).decode()
