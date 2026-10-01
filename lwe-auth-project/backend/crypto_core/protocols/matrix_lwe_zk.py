"""Plain (non-ring) instantiation of the Fiat-Shamir-with-aborts template.

Relation: A S + E = B~ (mod q) with A in Z_q^{m x n} shared, S in Z^{n x ell}
and E in Z^{m x ell} short. The key holds ell secret columns (Bai-Galbraith
2014) so that a single sparse ternary challenge c in {-1,0,1}^ell of weight
kappa gives a challenge space of at least 128 bits; with one secret column the
proof would need about 128 parallel repetitions.

Subclasses choose the secret distribution and how B~ is obtained:
``standard_lwe`` and ``binary_lwe`` sample E (B = A S + E), ``lwr`` derives E
deterministically from rounding (B = round_p(A S), B~ = (q/p) B).
"""

from __future__ import annotations

from typing import Any

import numpy as np

from crypto_core.exceptions import InvalidProtocolDataError
from crypto_core.interface import SerializedData
from crypto_core.lwe import codec, sampling
from crypto_core.protocols.lattice_zk import (
    MAX_MODULUS,
    Context,
    LatticeZKProtocol,
    ResponseComponent,
    field,
    require_int,
    require_mapping,
    validate_proof_parameters,
)

DEFAULT_N = 1024
DEFAULT_M = 1024
DEFAULT_ELL = 128
DEFAULT_KAPPA = 31
DEFAULT_GAMMA = 1 << 17
DEFAULT_ETA = 2

_MAX_DIMENSION = 4096
_MAX_ELL = 1024
_MAX_ETA = 8
_MAX_MATRIX_COEFFICIENTS = 1 << 24


def resolve_matrix_dimensions(
    overrides: SerializedData,
    default_q: int,
) -> dict[str, int]:
    """Validate the tunables shared by every matrix candidate."""
    n = require_int(overrides.get("n", DEFAULT_N), "n", 16, _MAX_DIMENSION)
    m = require_int(overrides.get("m", DEFAULT_M), "m", 16, _MAX_DIMENSION)
    q = require_int(overrides.get("q", default_q), "q", 1 << 10, MAX_MODULUS)
    ell = require_int(overrides.get("ell", DEFAULT_ELL), "ell", 16, _MAX_ELL)
    kappa = require_int(overrides.get("kappa", DEFAULT_KAPPA), "kappa", 1, ell)
    gamma = require_int(overrides.get("gamma", DEFAULT_GAMMA), "gamma", 2)
    eta = require_int(overrides.get("eta", DEFAULT_ETA), "eta", 1, _MAX_ETA)
    if m * n > _MAX_MATRIX_COEFFICIENTS:
        raise InvalidProtocolDataError(
            f"La matriz A excede {_MAX_MATRIX_COEFFICIENTS} coeficientes."
        )
    return {"n": n, "m": m, "q": q, "ell": ell, "kappa": kappa, "gamma": gamma, "eta": eta}


class MatrixLWEZKProtocol(LatticeZKProtocol):
    """Shared matrix relation; subclasses define secret and key construction."""

    # -- subclass hooks ------------------------------------------------------------

    def _secret_bound(self, parameters: SerializedData) -> int:
        """Largest |coefficient| of S."""
        raise NotImplementedError

    def _error_bound(self, parameters: SerializedData) -> int:
        """Largest |coefficient| of E."""
        raise NotImplementedError

    def _public_modulus(self, parameters: SerializedData) -> int:
        """Modulus of the transmitted public key coefficients."""
        return parameters["q"]

    def _sample_secret(self, parameters: SerializedData) -> np.ndarray:
        raise NotImplementedError

    def _encode_secret(self, secret: np.ndarray, parameters: SerializedData) -> str:
        raise NotImplementedError

    def _decode_secret(self, value: Any, parameters: SerializedData) -> np.ndarray:
        raise NotImplementedError

    def _derive_public_key(
        self,
        parameters: SerializedData,
        product: np.ndarray,
    ) -> tuple[np.ndarray, np.ndarray]:
        """From A S mod q return (public key B, witness error E)."""
        raise NotImplementedError

    def _lift_public_key(self, parameters: SerializedData, public: np.ndarray) -> np.ndarray:
        """Return B~ in Z_q such that A S + E = B~ (mod q)."""
        return public

    # -- validation ------------------------------------------------------------------

    def _validate(self, parameters: dict[str, Any]) -> None:
        kappa = parameters["kappa"]
        validate_proof_parameters(
            parameters["q"],
            parameters["gamma"],
            [
                (parameters["n"], kappa * self._secret_bound(parameters)),
                (parameters["m"], kappa * self._error_bound(parameters)),
            ],
            parameters["ell"],
            kappa,
        )

    # -- relation --------------------------------------------------------------------

    def _generate_shared(self, parameters: SerializedData) -> SerializedData:
        matrix_a = sampling.sample_uniform_mod_q(
            (parameters["m"], parameters["n"]),
            parameters["q"],
        )
        return {"matrix_a": codec.encode_unsigned(matrix_a, parameters["q"])}

    def _load_shared(self, context: Context, system_parameters: SerializedData) -> np.ndarray:
        parameters = context.parameters
        _, matrix_a = codec.decode_unsigned(
            field(system_parameters, "matrix_a", "los parámetros del sistema"),
            "matrix_a",
            (parameters["m"], parameters["n"]),
            parameters["q"],
        )
        return matrix_a

    def _generate_user_keys(
        self,
        context: Context,
        shared: np.ndarray,
    ) -> tuple[SerializedData, SerializedData]:
        parameters = context.parameters
        secret = self._sample_secret(parameters)
        # n * (q - 1) * ||S||_inf < 2^53 for every accepted parameter set, so the
        # BLAS product in float64 is exact.
        product = (
            np.rint(shared.astype(np.float64) @ secret.astype(np.float64)).astype(np.int64)
            % parameters["q"]
        )
        public, error = self._derive_public_key(parameters, product)
        return (
            {"B": codec.encode_unsigned(public, self._public_modulus(parameters))},
            {
                "S": self._encode_secret(secret, parameters),
                "E": codec.encode_signed(error, self._error_bound(parameters)),
            },
        )

    def _load_public_key(
        self,
        context: Context,
        public_key: SerializedData,
    ) -> tuple[bytes, np.ndarray]:
        parameters = context.parameters
        public_key = require_mapping(public_key, "La clave pública")
        raw, public = codec.decode_unsigned(
            field(public_key, "B", "la clave pública"),
            "B",
            (parameters["m"], parameters["ell"]),
            self._public_modulus(parameters),
        )
        return raw, self._lift_public_key(parameters, public)

    def _load_witness(self, context: Context, private_key: dict[str, Any]) -> tuple[np.ndarray, np.ndarray]:
        parameters = context.parameters
        secret = self._decode_secret(field(private_key, "S", "la clave privada"), parameters)
        error = codec.decode_signed(
            field(private_key, "E", "la clave privada"),
            "E",
            (parameters["m"], parameters["ell"]),
            self._error_bound(parameters),
        )
        return secret, error

    def _response_layout(self, context: Context) -> tuple[ResponseComponent, ...]:
        parameters = context.parameters
        gamma, kappa = parameters["gamma"], parameters["kappa"]
        return (
            ResponseComponent("z1", (parameters["n"],), gamma, kappa * self._secret_bound(parameters)),
            ResponseComponent("z2", (parameters["m"],), gamma, kappa * self._error_bound(parameters)),
        )

    def _challenge_shape(self, context: Context) -> tuple[int, int]:
        return context.parameters["ell"], context.parameters["kappa"]

    def _commit(
        self,
        context: Context,
        shared: np.ndarray,
        masks: tuple[np.ndarray, ...],
    ) -> np.ndarray:
        y1, y2 = masks
        return (shared @ y1 + y2) % context.parameters["q"]

    def _witness_times_challenge(
        self,
        context: Context,
        witness: tuple[np.ndarray, np.ndarray],
        challenge: np.ndarray,
    ) -> tuple[np.ndarray, ...]:
        secret, error = witness
        return secret @ challenge, error @ challenge

    def _reconstruct_commitment(
        self,
        context: Context,
        shared: np.ndarray,
        public_material: np.ndarray,
        responses: tuple[np.ndarray, ...],
        challenge: np.ndarray,
    ) -> np.ndarray:
        z1, z2 = responses
        return (shared @ z1 + z2 - public_material @ challenge) % context.parameters["q"]
