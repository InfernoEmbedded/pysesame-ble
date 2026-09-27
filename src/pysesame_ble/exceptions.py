"""Exceptions for the sesame-ble library."""


class SesameError(Exception):
    """Base exception for all sesame-ble errors."""


class SesameConnectionError(SesameError):
    """Raised when connecting to a Sesame BLE device fails."""


class SesameAuthenticationError(SesameError):
    """Raised when authentication (handshake, login, signature verification) fails."""


class SesameCommandError(SesameError):
    """Raised when sending a command or parsing a response fails."""


class SesameRegistrationError(SesameError):
    """Raised when device registration / onboarding fails."""


class SesameKeyError(SesameError):
    """Raised when encryption keys or QR code data are invalid."""
