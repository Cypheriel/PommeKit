"""
Copyright (c) 2024  Cypheriel.

Secure Remote Password protocol implementation.

This module provides an implementation of the Secure Remote Password protocol, as defined in RFC 5054.
For now, only the client-side implementation is provided.
This implementation is designed to be compatible with the Apple SRP implementation, as used in the GrandSlam framework.

See:
  - https://datatracker.ietf.org/doc/html/rfc5054
"""

from __future__ import annotations

from functools import lru_cache
from hashlib import sha256
from importlib import resources
from typing import TYPE_CHECKING, Self

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh

from .._util.crypto import randbytes

if TYPE_CHECKING:
    from os import PathLike


@lru_cache
def _byte_length(value: int) -> int:
    """
    Calculate the byte length of an integer.

    :param value: The integer to calculate the byte length of.
    :return: The length of the integer in bytes.

    >>> _byte_length(255)
    1

    >>> _byte_length(256)
    2
    """
    return (value.bit_length() + 7) // 8


@lru_cache
def _to_bytes(value: int) -> bytes:
    r"""
    Convert an integer to a dynamically-sized bytes object.

    :param value: The integer to convert.
    :return: The bytes object.

    >>> _to_bytes(255)
    b'\xff'

    >>> _to_bytes(256)
    b'\x01\x00'
    """
    return value.to_bytes(_byte_length(value))


def _generate_safe_prime(generator: int = 2, key_size: int = 2048) -> tuple[int, int]:
    """
    Generate a safe prime and generator using cryptography's DH module.

    :return: The safe prime and generator.
    """
    dh_params = dh.generate_parameters(generator, key_size)
    return dh_params.parameter_numbers().p, dh_params.parameter_numbers().g


def _load_safe_prime(path: PathLike | None = None) -> tuple[int, int]:
    """
    Load the safe prime and generator from a DH parameters PEM file.

    By default, the parameters are loaded from the package resources.

    :param path: The path to the DHParams PEM file.
    :return: The safe prime and generator.
    """
    if path is None:
        path = resources.files(__package__) / "params.pem"

    with path.open("rb") as file:
        dh_params = serialization.load_pem_parameters(file.read())

    return dh_params.parameter_numbers().p, dh_params.parameter_numbers().g


@lru_cache
def _hash(*args: int | bytes, width: int | None = None, include_headers: bool = True) -> int:
    """
    Hash the provided arguments using SHA-256.

    In compliance with RFC 5054, the hash (by default) includes length headers for each argument.

    :param args: The arguments to hash.
    :param width: The width of the hash.
    :param include_headers: Whether to include length headers.
    :return: The hashed value, as an integer.
    """
    hash_data = sha256()

    for arg in args:
        if not isinstance(arg, (int, bytes)):
            msg = f"Expected int | bytes, got {type(arg)}."
            raise TypeError(msg)

        arg_data = _to_bytes(arg) if isinstance(arg, int) else arg

        if include_headers is True and width is not None:
            hash_data.update(bytes(width - len(arg_data)))

        hash_data.update(arg_data)

    return int.from_bytes(hash_data.digest())


class SRPUser:
    """
    Mostly RFC 5054-compatible (by default) implementation of the Secure Remote Password protocol.

    This class is used to generate the client proof, and verify the server proof.
    """

    def __init__(
        self: Self,
        username: str,
        safe_prime: int | None = None,
        generator: int | None = None,
        private_ephemeral: int | None = None,
        *,
        generate_safe_prime: bool = False,
    ) -> None:
        """Initialize the SRP user."""
        self.username = username.encode()  # I
        """
        The user's identifying username.
        This value is provided by the user, and sent to the server, along with the user's public ephemeral value.

        `I`
        """

        _prime_args = (safe_prime, generator)
        _any_prime_args = any(_prime_args)
        if _any_prime_args and not all(_prime_args):
            msg = "All or none of safe_prime, generator must be provided."
            raise ValueError(msg)

        if not _any_prime_args and generate_safe_prime is False:
            safe_prime, generator = _load_safe_prime()

        elif generate_safe_prime is True:
            safe_prime, generator = _generate_safe_prime()

        self.safe_prime = safe_prime
        """
        The safe prime number.

        `N = 2q+1`, where q is prime
        """

        self.generator = generator
        """
        The generator number.

        `g`
        """

        self.multiplier = _hash(self.safe_prime, self.generator, width=_byte_length(self.safe_prime))
        """
        SRP-6a multiplier parameter

        `k = H(N, g)`
        """

        self.private_ephemeral: int = private_ephemeral or int.from_bytes(randbytes(32))
        """
        User's private ephemeral value, a random number.

        `a = random(32)`
        """

        self.public_ephemeral: bytes = _to_bytes(pow(self.generator, self.private_ephemeral, self.safe_prime))
        """
        User's public ephemeral value. This value is sent to the server, along with the user's username.

        `A = g^a % N`
        """

        self.salt: bytes | None = None
        """
        Salt received from the server.

        `s`
        """

        self.server_public_ephemeral: int | None = None
        """
        The server's public ephemeral value.

        `B`
        """

        self.scrambling_parameter: int | None = None
        """
        The scrambling parameter.

        `u = H(A, B)`
        """

        self.private_key: int | None = None
        """
        The user's private key.

        `x = H(s, H(I, ":", P))`
        """

        self.verifier: int | None = None
        """
        The server's password verifier.

        `v = g^x % N`
        """

        self.session_key: bytes | None = None
        """
        The user's session key.

        `S = (B - k * g^x)^(a + u * x) % N`
        """

        self.shared_key: bytes | None = None
        """
        The shared key.

        `K = H(S)`
        """

        self.client_proof: bytes | None = None
        """
        The client proof. This value is sent to the server to verify the user.

        `M(User) = H(H(N) XOR H(g), H(I), s, A, B, K)`
        """

        self.server_proof: bytes | None = None
        """
        The server proof, this value is used to verify the server.

        `M(Server) = H(A, M, K)`
        """

    def _xor_prime_and_generator_bytes(self: Self, *, include_padding: bool = True) -> bytes:
        """
        XOR each byte of the hashed safe prime and generator.

        :param include_padding: Whether to include padding in the generator bytes.
        :return: The XORed bytes.
        """
        generator = self.generator.to_bytes(_byte_length(self.safe_prime))
        if include_padding is False:
            generator = generator.lstrip(b"\x00")

        prime_hashed = sha256(_to_bytes(self.safe_prime)).digest()
        generator_hashed = sha256(generator).digest()

        return b"".join((p_byte ^ g_byte).to_bytes() for p_byte, g_byte in zip(prime_hashed, generator_hashed))

    def _calculate_client_proof(self: Self) -> bytes:
        """
        Calculate the client proof.

        :return: The client proof.
        """
        return sha256(
            self._xor_prime_and_generator_bytes()
            + sha256(self.username).digest()
            + self.salt
            + self.public_ephemeral
            + _to_bytes(self.server_public_ephemeral)
            + self.shared_key,
        ).digest()

    def _generate_private_key(self: Self, password: bytes, salt: int | bytes, *, include_username: bool = False) -> int:
        """
        Generate the private key for the user.

        :param password: The user's password.
        :param salt: The salt provided by the server.
        :param include_username: Whether to include the username in the hash.
        :return:
        """
        username = self.username if include_username is True else b""

        return _hash(salt, _hash(username, b":", password, include_headers=False))

    def process_challenge(
        self: Self,
        password: str | bytes,
        salt: int | bytes,
        server_public_ephemeral: int | bytes,
    ) -> bytes:
        """
        Process the challenge from the server and generate the client proof.

        :param password: The user's password.
        :param salt: The salt provided by the server.
        :param server_public_ephemeral: The server's public ephemeral.
        :return: The client proof, also stored under `self.client_proof`.
        """
        if not isinstance(password, bytes):
            password = password.encode()

        if isinstance(server_public_ephemeral, bytes):
            server_public_ephemeral = int.from_bytes(server_public_ephemeral)

        if isinstance(salt, int):
            salt = _to_bytes(salt)

        if server_public_ephemeral % self.safe_prime == 0:
            msg = "Server public ephemeral is invalid."
            raise ValueError(msg)

        self.salt = salt
        self.server_public_ephemeral = server_public_ephemeral

        self.scrambling_parameter = _hash(
            self.public_ephemeral,
            self.server_public_ephemeral,
            width=_byte_length(self.safe_prime),
        )
        self.private_key = self._generate_private_key(password, salt)

        self.verifier = pow(self.generator, self.private_key, self.safe_prime)

        self.session_key = _to_bytes(
            pow(
                (self.server_public_ephemeral - self.multiplier * self.verifier),
                (self.private_ephemeral + self.scrambling_parameter * self.private_key),
                self.safe_prime,
            ),
        )

        self.shared_key = sha256(self.session_key).digest()

        self.client_proof = self._calculate_client_proof()

        self.server_proof = sha256(self.public_ephemeral + self.client_proof + self.shared_key).digest()

        return self.client_proof

    def verify_session(self: Self, server_proof: bytes) -> bool:
        """
        Verify the server proof.

        :param server_proof: The server proof.
        :return: Whether the server proof is valid.
        """
        return server_proof == self.server_proof
