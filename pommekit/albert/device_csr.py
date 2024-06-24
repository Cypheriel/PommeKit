#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel

"""Module for generating a `CertificateSigningRequest` used for the request to Albert."""

from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import (
    CertificateSigningRequest,
    CertificateSigningRequestBuilder,
)
from cryptography.x509.oid import NameOID


def generate_device_csr(private_key: RSAPrivateKey) -> CertificateSigningRequest:
    """Generate a `CertificateSigningRequest` used for the request to Albert."""
    return CertificateSigningRequestBuilder(
        subject_name=x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Cupertino"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "iPhone"),
                x509.NameAttribute(NameOID.COMMON_NAME, str(uuid4())),
            ],
        ),
    ).sign(private_key, SHA256())
