from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from crypto_core.exceptions import ProtocolUnavailableError, UnknownProtocolError
from crypto_core.interface import AuthProtocol
from crypto_core.protocols.ecdsa import StandardECDSAProtocol
from crypto_core.protocols.lwe_zk import BinaryLWEProtocol, StandardLWEProtocol
from crypto_core.protocols.ring_lwe import RingLWEProtocol
from crypto_core.protocols.lwr_auth import LWRProtocol
from crypto_core.protocols.proposed_lwe import ProposedLWEAuthProtocol


@dataclass(frozen=True, slots=True)
class ProtocolSpec:
    protocol_id: str
    display_name: str
    family: str
    aliases: tuple[str, ...]
    declared_dependencies: tuple[str, ...]
    implementation_factory: Callable[[], AuthProtocol] | None
    development_note: str

    @property
    def available(self) -> bool:
        return self.implementation_factory is not None

    def require_implementation(self) -> AuthProtocol:
        if self.implementation_factory is None:
            raise ProtocolUnavailableError(
                f"'{self.protocol_id}' todavía no está implementado. {self.development_note}"
            )
        return self.implementation_factory()


# This catalog is the single source of truth for the six thesis candidates.
# Add an implementation_factory only when the complete protocol passes the
# common conformance tests. Do not register mathematical primitives as protocols.
_PROTOCOL_SPECS: tuple[ProtocolSpec, ...] = (
    ProtocolSpec(
        protocol_id="ecdsa",
        display_name="ECDSA P-256",
        family="elliptic-curve",
        aliases=("standard", "standard_ecdsa"),
        declared_dependencies=("cryptography",),
        implementation_factory=StandardECDSAProtocol,
        development_note="Baseline funcional de la comparación.",
    ),
    ProtocolSpec(
        protocol_id="standard_lwe",
        display_name="Standard LWE",
        family="lwe",
        aliases=("lwe",),
        declared_dependencies=("numpy",),
        implementation_factory=StandardLWEProtocol,
        development_note="Identificación Fiat-Shamir con abortos (NIZK en ROM) sobre LWE (secreto binomial centrado).",
    ),
    ProtocolSpec(
        protocol_id="binary_lwe",
        display_name="Binary LWE",
        family="lwe",
        aliases=(),
        declared_dependencies=("numpy",),
        implementation_factory=BinaryLWEProtocol,
        development_note="Identificación Fiat-Shamir con abortos (NIZK en ROM) sobre LWE con secreto binario.",
    ),
    ProtocolSpec(
        protocol_id="ring_lwe",
        display_name="Ring-LWE",
        family="ring-lwe",
        aliases=(),
        declared_dependencies=("numpy",),
        implementation_factory=RingLWEProtocol,
        development_note="Identificación Fiat-Shamir con abortos (NIZK en ROM) sobre Ring-LWE en Z_q[x]/(x^n+1).",
    ),
    ProtocolSpec(
        protocol_id="lwr",
        display_name="Learning With Rounding",
        family="lwr",
        aliases=("lwrounding", "lwr_auth"),
        declared_dependencies=("numpy",),
        implementation_factory=LWRProtocol,
        development_note="Identificación Fiat-Shamir con abortos (NIZK en ROM) sobre Learning With Rounding.",
    ),
    ProtocolSpec(
        protocol_id="proposed_lwe",
        display_name="Proposed LWE Protocol",
        family="lwe",
        aliases=("custom_lwe",),
        declared_dependencies=("numpy", "cryptography"),
        implementation_factory=ProposedLWEAuthProtocol,
        development_note=(
            "PQLite-Auth v2 con módulo dual: prueba Fiat-Shamir con abortos (NIZK en "
            "ROM) sobre q' = 8380417 con bits altos/bajos; token ML-KEM-768 + "
            "AES-256-GCM, tickets de un solo uso y acuerdo de clave sobre q = 3329. "
            "La dureza con rango de prueba 3 debe revisarse; ver README."
        ),
    ),
)

_BY_ID = {spec.protocol_id: spec for spec in _PROTOCOL_SPECS}
_ALIASES = {
    alias: spec.protocol_id
    for spec in _PROTOCOL_SPECS
    for alias in spec.aliases
}


def protocol_catalog() -> tuple[ProtocolSpec, ...]:
    return _PROTOCOL_SPECS


def available_protocol_names() -> tuple[str, ...]:
    return tuple(spec.protocol_id for spec in _PROTOCOL_SPECS if spec.available)


def get_protocol_spec(protocol_name: str) -> ProtocolSpec:
    normalized = protocol_name.strip().lower()
    canonical = _ALIASES.get(normalized, normalized)
    try:
        return _BY_ID[canonical]
    except KeyError as exc:
        raise UnknownProtocolError(
            f"Protocolo '{protocol_name}' no encontrado."
        ) from exc


def get_protocol(protocol_name: str) -> AuthProtocol:
    return get_protocol_spec(protocol_name).require_implementation()
