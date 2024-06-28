#  PommeKit - Python library with various tools for interacting with Apple services and APIs
#  Copyright (C) 2024  Cypheriel
from io import BytesIO

from pommekit.apns.types import PUSH_TOKEN_TRANSFORMER, UnknownFlag


def test_connect_packet():
    from pommekit.apns.commands import ConnectCommand

    push_token = PUSH_TOKEN_TRANSFORMER.deserialize(b"Meow, world!")
    command = ConnectCommand(
        push_token=push_token,
        certificate=None,
        nonce=None,
        signature=None,
    )

    serialized_push_token = PUSH_TOKEN_TRANSFORMER.serialize(push_token)

    command_data = bytes(command)
    stream = BytesIO(command_data)

    command_id = stream.read(1)
    assert command_id == b"\x07"

    packet_length = int.from_bytes(stream.read(4))
    assert packet_length == len(command_data[5:])

    push_token_item_id = int.from_bytes(stream.read(1))
    assert push_token_item_id == 0x01

    push_token_item_length = int.from_bytes(stream.read(2))
    assert push_token_item_length == len(serialized_push_token)

    push_token_item_data = stream.read(push_token_item_length)
    assert push_token_item_data == serialized_push_token

    state_item_id = int.from_bytes(stream.read(1))
    assert state_item_id == 0x02

    state_item_length = int.from_bytes(stream.read(2))
    assert state_item_length == 1

    state_item_data = stream.read(state_item_length)
    assert state_item_data == b"\x01"

    flags_item_id = int.from_bytes(stream.read(1))
    assert flags_item_id == 0x05

    flags_item_length = int.from_bytes(stream.read(2))
    assert flags_item_length == 4

    flags_item_data = stream.read(flags_item_length)
    assert flags_item_data == UnknownFlag.IS_ROOT.to_bytes(length=4)

    interface_item_id = int.from_bytes(stream.read(1))
    assert interface_item_id == 0x06

    interface_item_length = int.from_bytes(stream.read(2))
    assert interface_item_length == 1

    interface_item_data = stream.read(interface_item_length)
    assert interface_item_data == b"\x01"

    carrier_item_id = int.from_bytes(stream.read(1))
    assert carrier_item_id == 0x08

    carrier_item_length = int.from_bytes(stream.read(2))
    assert carrier_item_length == 4

    carrier_item_data = stream.read(carrier_item_length)
    assert carrier_item_data == b"WiFi"

    os_version_item_id = int.from_bytes(stream.read(1))
    assert os_version_item_id == 0x09

    os_version_item_length = int.from_bytes(stream.read(2))
    assert os_version_item_length == 6

    os_version_item_data = stream.read(os_version_item_length)
    assert os_version_item_data == b"10.6.4"

    os_build_item_id = int.from_bytes(stream.read(1))
    assert os_build_item_id == 0x0A

    os_build_item_length = int.from_bytes(stream.read(2))
    assert os_build_item_length == 6

    os_build_item_data = stream.read(os_build_item_length)
    assert os_build_item_data == b"10.6.4"

    hardware_version_item_id = int.from_bytes(stream.read(1))
    assert hardware_version_item_id == 0x0B

    hardware_version_item_length = int.from_bytes(stream.read(2))
    assert hardware_version_item_length == 10

    hardware_version_item_data = stream.read(hardware_version_item_length)
    assert hardware_version_item_data == b"windows1,1"

    protocol_version_item_id = int.from_bytes(stream.read(1))
    assert protocol_version_item_id == 0x10

    protocol_version_item_length = int.from_bytes(stream.read(2))
    assert protocol_version_item_length == 2

    protocol_version_item_data = stream.read(protocol_version_item_length)
    assert protocol_version_item_data == b"\x00\x02"

    redirect_count_item_id = int.from_bytes(stream.read(1))
    assert redirect_count_item_id == 0x11

    redirect_count_item_length = int.from_bytes(stream.read(2))
    assert redirect_count_item_length == 2

    redirect_count_item_data = stream.read(redirect_count_item_length)
    assert redirect_count_item_data == b"\x00\x00"

    assert stream.read() == b""
    assert stream.tell() == len(command_data)
