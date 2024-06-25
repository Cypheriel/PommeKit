#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate

from pommekit.albert.activation import request_push_certificate


@pytest.mark.asyncio()
async def test_windows_provisioning():
    push_key, push_cert = await request_push_certificate(
        activation_info_content={
            "ActivationRandomness": str(uuid4()).upper(),
            "ActivationState": "Unactivated",
            "DeviceClass": "Windows",
            "ProductType": "windows1,1",
            "ProductVersion": "10.6.4",
            "BuildVersion": "10.6.4",
            "SerialNumber": "WindowSerial",
            "UniqueDeviceID": str(uuid4()).upper(),
        },
    )

    assert isinstance(push_key, RSAPrivateKey)
    assert isinstance(push_cert, Certificate)


@pytest.mark.asyncio()
async def test_macos_provisioning():
    push_key, push_cert = await request_push_certificate(
        activation_info_content={
            "ActivationRandomness": str(uuid4()).upper(),
            "ActivationState": "Unactivated",
            "DeviceClass": "MacOS",
            "ProductType": "Macmini8,1",
            "ProductVersion": "12.6.6",
            "BuildVersion": "21G646",
            "SerialNumber": "C07CN17VPJH7",
            "UniqueDeviceID": str(uuid4()).upper(),
        },
    )

    assert isinstance(push_key, RSAPrivateKey)
    assert isinstance(push_cert, Certificate)


@pytest.mark.asyncio()
async def test_bs_provisioning():
    push_key, push_cert = await request_push_certificate(
        activation_info_content={
            "ActivationRandomness": "00000000-0000-0000-0000-000000000000",
            "ActivationState": "Unactivated",
            "DeviceClass": "MacOS",
            "ProductType": "Crapmini99,99",
            "ProductVersion": "420.69.0",
            "BuildVersion": "ABCDEF",
            "SerialNumber": "0123456789AB",
            "UniqueDeviceID": "00000000-0000-0000-0000-000000000000",
        },
    )

    assert isinstance(push_key, RSAPrivateKey)
    assert isinstance(push_cert, Certificate)


@pytest.mark.asyncio()
async def test_minimal_provisioning():
    push_key, push_cert = await request_push_certificate(
        activation_info_content={
            "ActivationState": "0",
            "DeviceClass": "MacOS",
            "ProductType": "0",
            "UniqueDeviceID": "00",
        },
    )

    assert isinstance(push_key, RSAPrivateKey)
    assert isinstance(push_cert, Certificate)
