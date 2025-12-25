"""CA-specific exceptions for DocSeal."""


class CAError(Exception):
    """Base error for CA operations."""


class CAAlreadyInitialized(CAError):
    """Raised when the CA is already initialized."""


class CAInitializationError(CAError):
    """Raised when initializing or exporting the CA fails."""


class InvalidPassword(CAError):
    """Raised when an invalid password is provided for PKCS12 exports."""


__all__ = [
    "CAError",
    "CAAlreadyInitialized",
    "CAInitializationError",
    "InvalidPassword",
]
