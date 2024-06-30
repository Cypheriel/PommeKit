#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel
"""Package for device-related classes and enums."""

from ._components import (
    AnisetteHeaders,
    APNsCredentialsComponent,
    DeviceInfoComponent,
    MachineDataComponent,
    NoneProvider,
    ProvidesADIPB,
    ProvidesAnisetteHeaders,
    ProvidesAPNsCredentials,
    ProvidesClientInfo,
    ProvidesDeviceInfo,
    ProvidesIdentifier,
    ProvidesMachineData,
    ProvidesMachineID,
    ProvidesOneTimePassword,
    ProvidesPushKeypair,
    ProvidesPushToken,
    ProvidesRoutingInfo,
    ProvidesSerialNumber,
    ProvidesUserAgent,
)
from ._device import SimulatedDevice as Device
from ._operating_system import OperatingSystem

__all__ = [
    "APNsCredentialsComponent",
    "AnisetteHeaders",
    "Device",
    "DeviceInfoComponent",
    "MachineDataComponent",
    "NoneProvider",
    "OperatingSystem",
    "ProvidesADIPB",
    "ProvidesAPNsCredentials",
    "ProvidesAnisetteHeaders",
    "ProvidesClientInfo",
    "ProvidesDeviceInfo",
    "ProvidesIdentifier",
    "ProvidesMachineData",
    "ProvidesMachineID",
    "ProvidesOneTimePassword",
    "ProvidesPushKeypair",
    "ProvidesPushToken",
    "ProvidesRoutingInfo",
    "ProvidesSerialNumber",
    "ProvidesUserAgent",
]
