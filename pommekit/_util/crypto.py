#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel

from __future__ import annotations

import re
from base64 import b64encode
from random import SystemRandom
from typing import TYPE_CHECKING, Final, Protocol

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.serialization import KeySerializationEncryption

PEM_EXPRESSION = re.compile(r"""-----(BEGIN|END) ([A-Z]+ ?)+-----""")

SYSTEM_RANDOM: Final = SystemRandom()
randint: Final = SYSTEM_RANDOM.randint
randbytes: Final = SYSTEM_RANDOM.randbytes
getrandbits = SYSTEM_RANDOM.getrandbits


class PrivateKey(Protocol):
    def private_bytes(
        self: PrivateKey,
        encoding: Encoding,
        format: PrivateFormat,  # noqa: A002
        encryption_algorithm: KeySerializationEncryption,
    ) -> bytes: ...


class PublicKey(Protocol):
    def public_bytes(
        self: PublicKey,
        encoding: Encoding,
    ) -> bytes: ...


def b64encoded_der(
    credential: PrivateKey | PublicKey | bytes | str,
) -> bytes:
    """
    Convert a credential to a base64-encoded DER.

    :param credential: A `cryptography` credential, or a credential (byte-)string in PEM format.
    :return: The base64-encoded DER representation of the credential.

    >>> from cryptography.hazmat.primitives.asymmetric import rsa
    >>> key = rsa.generate_private_key(65537, 2048)
    >>> expected = b64encoded_der(key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
    >>> b64encoded_der(key) == expected
    True
    """
    if hasattr(credential, "private_bytes"):
        result = b64encode(credential.private_bytes(Encoding.DER, PrivateFormat.TraditionalOpenSSL, NoEncryption()))

    elif hasattr(credential, "public_bytes"):
        result = b64encode(credential.public_bytes(Encoding.DER))

    elif isinstance(credential, bytes):
        result = PEM_EXPRESSION.sub("", credential.decode()).strip().encode()

    elif isinstance(credential, str):
        result = PEM_EXPRESSION.sub("", credential).strip().encode()

    else:
        msg = f"Expected supported PEM, got {type(credential)}."
        raise TypeError(msg)

    return result.replace(b"\n", b"")


def construct_identity_key(
    public_signing_key: ec.EllipticCurvePublicKey,
    public_encryption_key: rsa.RSAPublicKey,
) -> bytes:
    """Construct an identity key from the public signing and encryption keys."""
    return (
        b"\x30\x81\xf6\x81\x43\x00\x41"
        + public_signing_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        + b"\x82\x81\xae\x00\xac"
        + public_encryption_key.public_bytes(Encoding.DER, PublicFormat.PKCS1)
    )
