from typing import Dict

from crypto_core.exceptions import ProtocolUnavailableError, UnknownProtocolError
from crypto_core.interface import AuthProtocol
from crypto_core.protocols.ecdsa import StandardECDSAProtocol

# Public API identifiers are kept stable. The implementation exposes its own
# canonical name through AuthProtocol.name when that metadata is needed.
_AVAILABLE_PROTOCOLS: Dict[str, AuthProtocol] = {
    "standard": StandardECDSAProtocol(),
}

# These identifiers existed in the prototype, but their authentication flows
# were incomplete and verify_response() returned True unconditionally. Keeping
# them explicit here prevents accidental use while preserving a clear migration
# path for their later Sage-based implementations.
_UNAVAILABLE_PROTOCOLS = {
    "lwe": "Standard LWE todavía no tiene un flujo de autenticación verificable implementado.",
    "standard_lwe": "Standard LWE todavía no tiene un flujo de autenticación verificable implementado.",
    "binary_lwe": "Binary-Secret LWE todavía no tiene un flujo de autenticación verificable implementado.",
}

_ALIASES = {
    "standard_ecdsa": "standard",
}


def available_protocol_names() -> tuple[str, ...]:
    """Return stable public identifiers for protocols that are safe to invoke."""
    return tuple(_AVAILABLE_PROTOCOLS.keys())


def get_protocol(protocol_name: str) -> AuthProtocol:
    """Resolve a public protocol identifier or fail with a domain-specific error."""
    normalized_name = protocol_name.strip().lower()
    normalized_name = _ALIASES.get(normalized_name, normalized_name)

    if normalized_name in _UNAVAILABLE_PROTOCOLS:
        raise ProtocolUnavailableError(_UNAVAILABLE_PROTOCOLS[normalized_name])

    try:
        return _AVAILABLE_PROTOCOLS[normalized_name]
    except KeyError as exc:
        raise UnknownProtocolError(
            f"Protocolo '{protocol_name}' no encontrado."
        ) from exc
