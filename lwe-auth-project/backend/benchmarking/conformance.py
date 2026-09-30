from __future__ import annotations

import copy

from benchmarking.serialization import canonical_json_bytes
from crypto_core.exceptions import InvalidProtocolDataError
from crypto_core.interface import AuthProtocol


class ProtocolConformanceError(RuntimeError):
    pass


def _tamper_json_value(value):
    """Return a minimally modified JSON-compatible value for negative tests."""
    if isinstance(value, dict):
        if not value:
            return {"__tampered__": True}
        mutated = copy.deepcopy(value)
        first_key = next(iter(mutated))
        mutated[first_key] = _tamper_json_value(mutated[first_key])
        return mutated
    if isinstance(value, list):
        if not value:
            return ["__tampered__"]
        mutated = copy.deepcopy(value)
        mutated[0] = _tamper_json_value(mutated[0])
        return mutated
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, float):
        return value + 1.0
    if isinstance(value, str):
        return value + "A"
    if value is None:
        return "__tampered__"
    raise ProtocolConformanceError(
        f"Tipo no JSON inesperado durante prueba negativa: {type(value).__name__}."
    )


def run_conformance_checks(
    protocol: AuthProtocol,
    parameters: dict,
) -> dict[str, bool]:
    """Fail fast when a candidate does not implement the common auth semantics."""
    system_parameters = protocol.generate_system_parameters(**parameters)
    canonical_json_bytes(system_parameters)
    original_system = copy.deepcopy(system_parameters)

    public_key, private_key = protocol.generate_keypair(system_parameters, **parameters)
    canonical_json_bytes(public_key)
    canonical_json_bytes(private_key)

    original_public = copy.deepcopy(public_key)
    original_private = copy.deepcopy(private_key)

    challenge_a = protocol.generate_challenge(system_parameters, public_key)
    challenge_b = protocol.generate_challenge(system_parameters, public_key)
    canonical_json_bytes(challenge_a)
    canonical_json_bytes(challenge_b)

    if challenge_a == challenge_b:
        raise ProtocolConformanceError(
            "El protocolo generó dos desafíos consecutivos idénticos; el benchmark "
            "requiere desafíos frescos para reducir riesgo de replay."
        )

    response = protocol.solve_challenge(
        system_parameters,
        private_key,
        challenge_a,
    )
    canonical_json_bytes(response)

    if not protocol.verify_response(
        system_parameters,
        public_key,
        challenge_a,
        response,
    ):
        raise ProtocolConformanceError(
            "Una respuesta válida no superó la verificación del protocolo."
        )

    if protocol.verify_response(
        system_parameters,
        public_key,
        challenge_b,
        response,
    ):
        raise ProtocolConformanceError(
            "Una respuesta fue aceptada para un desafío distinto."
        )

    tampered_response = _tamper_json_value(response)
    try:
        tampered_accepted = protocol.verify_response(
            system_parameters,
            public_key,
            challenge_a,
            tampered_response,
        )
    except InvalidProtocolDataError:
        tampered_accepted = False
    if tampered_accepted:
        raise ProtocolConformanceError(
            "El protocolo aceptó una respuesta modificada."
        )

    second_public, _ = protocol.generate_keypair(system_parameters, **parameters)
    if protocol.verify_response(
        system_parameters,
        second_public,
        challenge_a,
        response,
    ):
        raise ProtocolConformanceError(
            "Una respuesta fue aceptada con una clave pública distinta."
        )

    if (
        system_parameters != original_system
        or public_key != original_public
        or private_key != original_private
    ):
        raise ProtocolConformanceError(
            "Las operaciones del protocolo modificaron material de entrada."
        )

    return {
        "json_serializable": True,
        "system_setup_json_serializable": True,
        "fresh_challenges": True,
        "valid_round_trip": True,
        "rejects_replayed_response_on_new_challenge": True,
        "rejects_tampered_response": True,
        "rejects_response_under_other_public_key": True,
        "does_not_mutate_inputs": True,
    }
