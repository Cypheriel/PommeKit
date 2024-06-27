#  Copyright (C) 2024  Cypheriel
"""Exceptions raised by the Anisette provider."""


class AnisetteProvisioningError(BaseException):
    """Base exception for Anisette provisioning errors."""


class ProvisioningURLFetchError(AnisetteProvisioningError):
    """Exception raised when fetching the provisioning URLs fails."""


class ClientInfoFetchError(AnisetteProvisioningError):
    """Exception raised when fetching the client info fails."""


class StartProvisioningRequestError(AnisetteProvisioningError):
    """Exception raised when the start provisioning request fails."""

    def __init__(self, status_code: int, response_content: bytes) -> None:
        """Initialize the exception with the status code and response content."""
        super().__init__(f"StartProvisioning request returned in error. ({status_code}) {response_content = }")


class EndProvisioningRequestError(AnisetteProvisioningError):
    """Exception raised when the end provisioning request fails."""

    def __init__(self, status_code: int, response_content: bytes) -> None:
        """Initialize the exception with the status code and response content."""
        super().__init__(f"EndProvisioning request returned in error. ({status_code}) {response_content = }")


class UnexpectedRemoteResponseError(AnisetteProvisioningError):
    """Exception raised when an unexpected response is received from the Anisette provider."""

    def __init__(self, response: dict) -> None:
        """Initialize the exception with the response."""
        super().__init__(f"Unexpected response from Anisette provider: {response = }")
