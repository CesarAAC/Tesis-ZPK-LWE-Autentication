from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from crypto_core.exceptions import ProtocolUnavailableError, UnknownProtocolError
from crypto_core.interface import AuthProtocol
from crypto_core.protocols.ecdsa import StandardECDSAProtocol
from crypto_core.protocols.regev_lwe import BinaryLWEProtocol, StandardLWEProtocol


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
        development_note=(
            "Regev LWE con secreto uniforme en Z_q y desafío por encriptación "
            "con verificación Fujisaki-Okamoto."
        ),
    ),
    ProtocolSpec(
        protocol_id="binary_lwe",
        display_name="Binary LWE",
        family="lwe",
        aliases=(),
        declared_dependencies=("numpy",),
        implementation_factory=BinaryLWEProtocol,
        development_note=(
            "Regev LWE con secreto binario y desafío por encriptación "
            "con verificación Fujisaki-Okamoto."
        ),
    ),
    ProtocolSpec(
        protocol_id="ring_lwe",
        display_name="Ring-LWE",
        family="ring-lwe",
        aliases=(),
        declared_dependencies=(),
        implementation_factory=None,
        development_note="Candidato reservado para implementación posterior.",
    ),
    ProtocolSpec(
        protocol_id="lwr",
        display_name="Learning With Rounding",
        family="lwr",
        aliases=("lwrounding", "lwr_auth"),
        declared_dependencies=(),
        implementation_factory=None,
        development_note="Candidato reservado para implementación posterior.",
    ),
    ProtocolSpec(
        protocol_id="proposed_lwe",
        display_name="Proposed LWE Protocol",
        family="lwe",
        aliases=("custom_lwe",),
        declared_dependencies=(),
        implementation_factory=None,
        development_note="Reservado para el protocolo diseñado en la tesis.",
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
