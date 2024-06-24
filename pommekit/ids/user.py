#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel
"""Module containing the IDSUser class."""

from __future__ import annotations

import asyncio
import json
import logging
import plistlib
from asyncio import Event
from base64 import b64decode, b64encode
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal, Self
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA1, SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from cryptography.x509 import (
    Certificate,
    CertificateSigningRequestBuilder,
    Name,
    NameAttribute,
    NameOID,
    load_der_x509_certificate,
    load_pem_x509_certificate,
)
from httpx import AsyncClient

from .._util.crypto import b64encoded_der, construct_identity_key, randbytes
from .._util.exponential_backoff import ExponentialBackoff
from ..apns.protocol.transformers import PUSH_TOKEN_TRANSFORMER, Nonce
from ..bags import ids_bag
from ..gsa import AUStatus, GSAClient
from ..status_codes import AppleStatusCode

if TYPE_CHECKING:
    from collections.abc import Callable
    from os import PathLike

    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

AUTHENTICATE_USER_KEY: Final = "vc-profile-authenticate"
AUTHENTICATE_USER_URL: Final = ids_bag[AUTHENTICATE_USER_KEY]

AUTHENTICATE_DEVICE_KEY: Final = "id-authenticate-ds-id"
AUTHENTICATE_DEVICE_URL: Final = ids_bag[AUTHENTICATE_DEVICE_KEY]

GET_HANDLES_KEY: Final = "id-get-handles"
GET_HANDLES_URL: Final = ids_bag[GET_HANDLES_KEY]

REGISTER_DEVICE_KEY: Final = "id-register"
REGISTER_DEVICE_URL: Final[str] = ids_bag[REGISTER_DEVICE_KEY]


logger = logging.getLogger(__name__)


class IDSError(Exception):
    """Generic exception for IDS-related errors."""


class IDSTwoFactorRequiredError(IDSError):
    """Exception raised when two-factor authentication is required but not given."""


class IDSTwoFactorInvalidError(IDSError):
    """Exception raised when the two-factor authentication code is invalid."""


def _to_length_value(value: bytes, length_size: int = 4) -> bytes:
    """Prepend the length of the value to the value."""
    return len(value).to_bytes(length_size) + value


class IDSUser:
    """Class representing a single Apple ID user."""

    @property
    def is_authenticated(self: Self) -> bool:
        """Whether the user is authenticated."""
        authenticated = self.on_authenticated_event.is_set()
        if not authenticated:
            authenticated = self.auth_token is not None and self.profile_id is not None

        return authenticated

    @property
    def is_device_authenticated(self: Self) -> bool:
        """Whether the user is device-authenticated."""
        device_authenticated = self.on_device_authenticated_event.is_set()
        if not device_authenticated:
            device_authenticated = self.private_key is not None and self.certificate is not None

        return device_authenticated

    @property
    def is_fully_authenticated(self: Self) -> bool:
        """Whether the user is fully authenticated and handles are available."""
        return len(self.handles) > 0

    @property
    def is_device_registered(self: Self) -> bool:
        """Whether the device is registered under the user."""
        return (
            self.device_certificate is not None
            and datetime.now().astimezone() < self.device_certificate.not_valid_after_utc.astimezone()
        )

    def __init__(
        self: Self,
        apple_id: str,
        anisette_provider: Callable[[], dict[str, str]],
        push_token_provider: Callable[[], str] | None = None,
        push_key_provider: Callable[[], RSAPrivateKey] | None = None,
        push_cert_provider: Callable[[], Certificate] | None = None,
    ) -> None:
        """Initialize a new instance of the IDSUser class."""
        self.apple_id = apple_id
        self._anisette_provider = anisette_provider

        self.push_key_provider = push_key_provider
        self.push_cert_provider = push_cert_provider
        self.push_token_provider = lambda: PUSH_TOKEN_TRANSFORMER.serialize(push_token_provider())

        self.password: str | None = None
        self.private_key: RSAPrivateKey | None = None
        self.certificate: Certificate | None = None
        self.profile_id: str | None = None
        self.auth_token: str | None = None
        self.signing_key: EllipticCurvePrivateKey | None = None
        self.encryption_key: RSAPrivateKey | None = None
        self.identity_key: bytes | None = None
        self.device_certificate: Certificate | None = None

        self.handles: list[dict[Literal["uri"], str]] = []

        self.requires_2fa: bool = False

        self.on_authenticated_event = Event()
        self.on_device_authenticated_event = Event()
        self.on_device_registered_event = Event()

        self._credential_file_names = {
            "auth_token": "auth_token.txt",
            "profile_id": "profile_id.txt",
            "private_key": "user.key",
            "certificate": "user.crt",
            "signing_key": "signing.key",
            "encryption_key": "encryption.key",
            "identity_key": "identity.key",
            "device_certificate": "device.crt",
        }

        self._client = AsyncClient(
            verify=False,  # noqa: S501
        )
        self._gsa_client = GSAClient(self._anisette_provider)
        self._2fa_code: str | None = None

        self._client.headers.update(
            {
                "x-protocol-version": "1630",
            },
        )

        self._auth_backoff = ExponentialBackoff(base_delay=4, max_retries=12)

    def _ensure_random_credentials(self: Self) -> None:
        """Ensure that random credentials are generated if they are not already present."""
        if self.private_key is None:
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        if self.signing_key is None:
            self.signing_key = ec.generate_private_key(ec.SECP256R1())

        if self.encryption_key is None:
            self.encryption_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        if self.identity_key is None:
            self.identity_key = construct_identity_key(self.signing_key.public_key(), self.encryption_key.public_key())

    def _generate_payload(
        self: Self,
        bag_key: str = "",
        query_string: str = "",
        payload: bytes = b"",
    ) -> tuple[bytes, bytes]:
        """Generate a payload for authentication."""
        nonce = bytes(Nonce(prefix=b"\x01"))

        return (
            b64encode(nonce),
            nonce
            + _to_length_value(bag_key.encode())
            + _to_length_value(query_string.encode())
            + _to_length_value(payload)
            + _to_length_value(self.push_token_provider()),
        )

    def _generate_signed_payload(
        self: Self,
        private_key: RSAPrivateKey,
        bag_key: str = "",
        query_string: str = "",
        payload: bytes = b"",
    ) -> tuple[bytes, bytes]:
        nonce, payload = self._generate_payload(bag_key, query_string, payload)
        signed_payload = b64encode(b"\x01\x01" + private_key.sign(payload, PKCS1v15(), SHA1()))  # noqa: S303
        return nonce, signed_payload

    def _generate_auth_headers(
        self: Self,
        bag_key: str = "",
        payload: bytes = b"",
        auth_suffix_number: int | None = None,
    ) -> dict[str, str]:
        push_nonce, push_sig = self._generate_signed_payload(self.push_key_provider(), bag_key=bag_key, payload=payload)
        auth_nonce, auth_sig = self._generate_signed_payload(self.private_key, bag_key=bag_key, payload=payload)

        auth_suffix = f"-{auth_suffix_number}" if auth_suffix_number is not None else ""
        return {
            "x-push-sig": push_sig,
            "x-push-nonce": push_nonce,
            "x-push-cert": b64encoded_der(self.push_cert_provider()),
            "x-push-token": PUSH_TOKEN_TRANSFORMER.deserialize(self.push_token_provider()),
            "x-auth-user-id": self.profile_id,
            f"x-auth-sig{auth_suffix}": auth_sig,
            f"x-auth-nonce{auth_suffix}": auth_nonce,
            f"x-auth-cert{auth_suffix}": b64encoded_der(self.certificate),
        }

    def log(self: Self, level: int, message: str, *args: ..., **kwargs: ...) -> None:
        """Log a message with the Apple ID as a prefix."""
        logger.log(level, f"[{self.apple_id}] " + f"{message}", *args, **kwargs, stacklevel=2)

    async def _send_authentication_request(self: Self, password: str, two_factor_code: str = "") -> None:
        """Send an authentication request to the IDS server."""
        if two_factor_code:
            self.log(logging.WARNING, "Two-factor authentication through IDS is not recommended. Please use GSA.")

        data = {
            "username": self.apple_id,
            "password": f"{password.strip()}{two_factor_code.strip()}",
        }

        self.log(logging.DEBUG, f"Authenticating through IDS via <{AUTHENTICATE_USER_URL}>.")

        response = await self._client.post(AUTHENTICATE_USER_URL, content=plistlib.dumps(data))
        response_data = plistlib.loads(response.content)
        status_code = AppleStatusCode(response_data.get("status"))

        self.log(logging.DEBUG, f"Response Payload: {json.dumps(response_data, indent=4)}")

        match status_code:
            case AppleStatusCode.SUCCESS:
                self.log(logging.DEBUG, "Successfully authenticated.")

            case AppleStatusCode.UNAUTHENTICATED:
                self.log(logging.WARNING, "User requires two-factor authentication.")
                raise IDSTwoFactorRequiredError

            case AppleStatusCode.ACTION_AUTHENTICATION_FAILED:
                if two_factor_code:
                    self.log(logging.ERROR, "Invalid two-factor authentication code.")
                    raise IDSTwoFactorInvalidError

            case AppleStatusCode.MISSING_REQUIRED_KEY:
                self.log(
                    logging.ERROR,
                    "2FA cannot be used to authenticate this account. Please use an app-specific password.",
                )

            case AppleStatusCode.ACTION_RETRY_WITH_DELAY:
                self._auth_backoff.max_delay = response_data.get("retry-interval", 60)

                sleep_time = self._auth_backoff.next()
                self.log(logging.INFO, f"Retrying authentication in {sleep_time} seconds.")
                await asyncio.sleep(sleep_time)

                await self._send_authentication_request(password, two_factor_code)
                return

            case _:
                self.log(logging.ERROR, f"Failed to authenticate. {status_code.name} ({status_code.value})")
                msg = f"Failed to authenticate. {status_code.name} ({status_code.value})"
                raise IDSError(msg)

        self.auth_token = response_data["auth-token"]
        self.profile_id = response_data["profile-id"]
        self._ensure_random_credentials()

    async def start_authentication(self: Self, password: str) -> None:
        """Start the authentication process."""
        self.password = password
        await self._gsa_client.authenticate(self.apple_id, password)

        match self._gsa_client.au_status:
            case AUStatus.COMPLETE:
                if self._gsa_client.pet_token is None:
                    msg = "GSA did not return a PET token."
                    raise ValueError(msg)

                self.log(logging.DEBUG, "Successfully authenticated through GSA.")
                await self._send_authentication_request(self._gsa_client.pet_token)

            case AUStatus.TRUSTED_DEVICE:
                await self._gsa_client.request_device_2fa()
                self.requires_2fa = True

            case AUStatus.SMS:
                msg = "SMS-based 2FA is not yet supported."
                raise NotImplementedError(msg)

    async def verify_2fa_code(self: Self, code: str) -> None:
        """Verify the two-factor authentication code."""
        success = await self._gsa_client.validate_device_2fa(code)
        await self._gsa_client.authenticate(self.apple_id, self.password)

        if success is True:
            await self._send_authentication_request(self._gsa_client.pet_token)
        else:
            await self._gsa_client.request_device_2fa()

        self.requires_2fa = not success

    async def authenticate_device(self: Self) -> None:
        """Authenticate the device with the IDS server."""
        if not self.private_key:
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        csr = CertificateSigningRequestBuilder(
            subject_name=Name(
                [
                    NameAttribute(NameOID.COMMON_NAME, randbytes(20).hex()),
                ],
            ),
        ).sign(self.private_key, SHA256())

        payload = plistlib.dumps(
            {
                "authentication-data": {"auth-token": self.auth_token},
                "csr": b64decode(b64encoded_der(csr)),
                "realm-user-id": self.profile_id,
            },
        )

        response = await self._client.post(AUTHENTICATE_DEVICE_URL, content=payload)
        response_data = plistlib.loads(response.content)

        status_code = AppleStatusCode(response_data.get("status"))
        if status_code is not AppleStatusCode.SUCCESS:
            self.log(logging.ERROR, f"Failed to authenticate device. Status: {status_code.name}")
            msg = f"Failed to authenticate device. Status: {status_code.name}"
            raise IDSError(msg)

        self.certificate = load_der_x509_certificate(response_data["cert"])
        self.log(logging.DEBUG, "Successfully authenticated device.")
        self.log(
            logging.DEBUG,
            f"Device certificate is valid until {self.certificate.not_valid_after_utc.astimezone()}.",
        )

        self.on_device_authenticated_event.set()

        await self.fetch_handles()

    async def fetch_handles(self: Self) -> None:
        """Fetch the user's handles, verifying that the user is authenticated."""
        if self.is_device_authenticated is False:
            msg = "User is not authenticated. Device authentication is required to fetch handles."
            raise ValueError(msg)

        if self.push_token_provider is None:
            msg = "Push token is required to fetch handles."
            raise ValueError(msg)

        logger.debug(f"Fetching handles from {GET_HANDLES_URL}.")

        response = await self._client.get(
            GET_HANDLES_URL,
            headers=self._generate_auth_headers(GET_HANDLES_KEY),
        )

        response_data = plistlib.loads(response.content)

        status_code = AppleStatusCode(response_data.get("status"))
        match status_code:
            case AppleStatusCode.SUCCESS:
                self.handles = response_data["handles"]
                self.log(logging.DEBUG, f"Successfully fetched handles: {self.handles}")

            case _:
                self.log(logging.ERROR, f"Failed to fetch handles. Status: {status_code.name}")
                msg = f"Failed to fetch handles. Status: {status_code.name}"
                raise IDSError(msg)

    async def register_device(
        self: Self,
        device_name: str,
        validation_data: str | bytes,
        operating_system: str,
        product_type: str,
        os_version: str,
        build_version: str,
    ) -> None:
        """Register the device under the user."""
        if self.is_fully_authenticated is False:
            msg = "User is not fully authenticated. Device registration is not possible."
            raise ValueError(msg)

        if operating_system == "iOS":
            self.log(logging.WARNING, "iOS registration is not yet supported! Attempting registration despite this...")

        if isinstance(validation_data, str):
            validation_data = b64decode(validation_data)

        payload_data = {
            "language": "en-US",
            "device-name": device_name,
            "hardware-version": product_type,
            "os-version": f"{operating_system},{product_type},{build_version}",
            "software-version": build_version,
            "private-device-data": {
                "u": uuid4().hex.upper(),
            },
            "services": [
                {
                    "capabilities": [{"flags": 1, "name": "Messenger", "version": 1}],
                    "service": "com.apple.madrid",
                    "sub-services": [
                        "com.apple.private.alloy.sms",
                        "com.apple.private.alloy.gelato",
                        "com.apple.private.alloy.biz",
                        "com.apple.private.alloy.gamecenter.imessage",
                    ],
                    "users": [
                        {
                            "client-data": {
                                "is-c2k-equipment": True,
                                "optionally-receive-typing-indicators": True,
                                "public-message-identity-key": self.identity_key,
                                "public-message-identity-version": 2,
                                "show-peer-errors": True,
                                "supports-ack-v1": True,
                                "supports-activity-sharing-v1": True,
                                "supports-audio-messaging-v2": True,
                                "supports-autoloopvideo-v1": True,
                                "supports-be-v1": True,
                                "supports-ca-v1": True,
                                "supports-fsm-v1": True,
                                "supports-fsm-v2": True,
                                "supports-fsm-v3": True,
                                "supports-ii-v1": True,
                                "supports-impact-v1": True,
                                "supports-inline-attachments": True,
                                "supports-keep-receipts": True,
                                "supports-location-sharing": True,
                                "supports-media-v2": True,
                                "supports-photos-extension-v1": True,
                                "supports-st-v1": True,
                                "supports-update-attachments-v1": True,
                            },
                            "uris": self.handles,
                            "user-id": self.profile_id,
                        },
                    ],
                },
            ],
            "validation-data": validation_data,
        }
        payload = plistlib.dumps(payload_data)

        user_agent = f"com.apple.invitation-registration [Mac OS X,{os_version},{build_version},{product_type}]"

        response = await self._client.post(
            REGISTER_DEVICE_URL,
            content=payload,
            headers={
                "User-Agent": user_agent,
                "x-auth-user-id-0": self.profile_id,
                **self._generate_auth_headers(REGISTER_DEVICE_KEY, payload, auth_suffix_number=0),
            },
        )

        response_data = plistlib.loads(response.content)
        status_code = AppleStatusCode(response_data.get("status"))

        match status_code:
            case AppleStatusCode.SUCCESS:
                self.log(logging.DEBUG, "Successfully registered device.")

            case _:
                msg = f"Failed to register device. Status: {status_code.name} ({status_code.value})"
                raise IDSError(msg)

        try:
            certificate_data = response_data["services"][0]["users"][0]["cert"]

        except KeyError as e:
            msg = "Failed to obtain certificate data."
            raise IDSError(msg) from e

        self.device_certificate = load_der_x509_certificate(certificate_data)
        self.on_device_registered_event.set()

        self.log(logging.DEBUG, "Successfully obtained device certificate.")
        self.log(logging.DEBUG, f"Certificate valid until {self.device_certificate.not_valid_after_utc.astimezone()}.")

    def write_credentials(self: Self, path: PathLike) -> None:
        """Write the user's credentials to a file."""
        path = path if isinstance(path, Path) else Path(path)
        user_path = path / self.apple_id
        user_path.mkdir(parents=True, exist_ok=True)

        for name, file_name in self._credential_file_names.items():
            credential_path = user_path / file_name

            credential = getattr(self, name, None)
            if credential is None:
                continue

            match name:
                case "auth_token" | "profile_id":
                    credential_path.write_text(credential)

                case "private_key" | "signing_key" | "encryption_key":
                    key_data = credential.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
                    credential_path.write_bytes(key_data)

                case "certificate" | "device_certificate":
                    certificate_data = credential.public_bytes(Encoding.PEM)
                    credential_path.write_bytes(certificate_data)

                case "identity_key":
                    credential_path.write_bytes(credential)

    def read_credentials(self: Self, path: PathLike) -> bool:
        """Read the user's credentials from a file."""
        path = path if isinstance(path, Path) else Path(path)

        if path.name != self.apple_id:
            path /= self.apple_id

        if not path.is_dir():
            return False

        self.log(logging.INFO, f"Reading credentials from {path}.")

        unknown = False
        for name, file_name in self._credential_file_names.items():
            credential_path = path / file_name
            if not credential_path.is_file():
                continue

            match name:
                case "auth_token" | "profile_id":
                    credential = credential_path.read_text()

                case "private_key" | "signing_key" | "encryption_key":
                    key_data = credential_path.read_bytes()
                    credential = load_pem_private_key(key_data, None)

                case "certificate" | "device_certificate":
                    certificate_data = credential_path.read_bytes()
                    credential = load_pem_x509_certificate(certificate_data)

                case "identity_key":
                    credential = credential_path.read_bytes()

                case _:
                    logger.debug(f"Unknown credential: {name}")
                    unknown = True
                    continue

            setattr(self, name, credential)

        self._ensure_random_credentials()

        return not unknown
