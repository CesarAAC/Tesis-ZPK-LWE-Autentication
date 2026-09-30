class CryptoCoreError(Exception):
    """Base exception for errors raised by the cryptographic core."""


class InvalidProtocolDataError(CryptoCoreError):
    """Raised when serialized cryptographic material is malformed or unsupported."""


class UnknownProtocolError(CryptoCoreError):
    """Raised when a protocol identifier is not registered."""


class ProtocolUnavailableError(CryptoCoreError):
    """Raised when a known protocol exists but is not ready for use."""
