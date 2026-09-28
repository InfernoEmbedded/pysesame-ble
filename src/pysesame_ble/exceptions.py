"""Exceptions for the sesame-ble library."""


class SesameError(Exception):
    """Base exception for all sesame-ble errors."""


class SesameConnectionError(SesameError):
    """Raised when connecting to a Sesame BLE device fails."""


class SesameAuthenticationError(SesameError):
    """Raised when authentication (handshake, login, signature verification) fails."""


class SesameCommandError(SesameError):
    """Raised when sending a command or parsing a response fails."""

    def __init__(self, message: str, error_code: int | None = None) -> None:
        super().__init__(message)
        self.error_code = error_code


class SesameRegistrationError(SesameError):
    """Raised when device registration / onboarding fails."""


class SesameKeyError(SesameError):
    """Raised when encryption keys or QR code data are invalid."""
