"""Fiat-Shamir-with-aborts identification from Learning With Rounding (``lwr``).

Key: B = round_p(A S) in Z_p^{m x ell} with S <- CBD_eta^{n x ell}; no error is
sampled. With q and p powers of two (p | q), lifting the key gives

    (q / p) B = A S + E  (mod q),   ||E||_inf <= q / (2p),

where E is the deterministic rounding error, computed by the prover at key
generation (sign and bound are checked by test_rounding_error_satisfies_lifted_relation).
The proof (``lattice_zk.py``) then runs on B~ = (q / p) B exactly as for
``standard_lwe``; zero knowledge only needs the hard bound on E, not its
distribution.

The key is an LWR instance with a short secret, not an LWE instance: its
hardness must be estimated as LWR. Treating the rounding error as LWE noise of
standard deviation about (q / p) / sqrt(12) is only a heuristic.

Defaults (n = m = 1024, q = 2^23, p = 2^20, eta = 2) keep the dimensions of
``standard_lwe``; the rounding error is bounded by 4. They are a starting
point, not a security proof, and must be estimated independently.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from crypto_core.exceptions import InvalidProtocolDataError
from crypto_core.interface import SerializedData
from crypto_core.lwe import codec, lwr, sampling
from crypto_core.protocols.lattice_zk import (
    common_fixed_parameters,
    require_int,
    require_power_of_two,
)
from crypto_core.protocols.matrix_lwe_zk import MatrixLWEZKProtocol, resolve_matrix_dimensions

DEFAULT_Q = 1 << 23
DEFAULT_P = 1 << 20


class LWRProtocol(MatrixLWEZKProtocol):
    """Learning With Rounding with a centered-binomial secret."""

    protocol_id = "lwr"

    def _fixed_parameters(self) -> SerializedData:
        return {
            "secret_distribution": "centered_binomial",
            "noise_mechanism": "deterministic_modulus_rounding",
            "rounding": "nearest",
            "matrix_distribution": "uniform_mod_q_shared",
            "key_shape": "ell_secret_columns",
            **common_fixed_parameters(),
        }

    def _resolve_tunable(self, overrides: SerializedData) -> SerializedData:
        parameters: dict[str, Any] = resolve_matrix_dimensions(overrides, DEFAULT_Q)
        q = require_power_of_two(parameters["q"], "q")
        p = require_power_of_two(
            require_int(overrides.get("p", DEFAULT_P), "p", 4),
            "p",
        )
        if 2 * p > q:
            raise InvalidProtocolDataError("LWR requiere p <= q / 2.")
        parameters["p"] = p
        self._validate(parameters)
        return parameters

    def _secret_bound(self, parameters: SerializedData) -> int:
        return parameters["eta"]

    def _error_bound(self, parameters: SerializedData) -> int:
        return parameters["q"] // (2 * parameters["p"])

    def _public_modulus(self, parameters: SerializedData) -> int:
        return parameters["p"]

    def _sample_secret(self, parameters: SerializedData) -> np.ndarray:
        return sampling.sample_centered_binomial(
            (parameters["n"], parameters["ell"]),
            parameters["eta"],
        )

    def _encode_secret(self, secret: np.ndarray, parameters: SerializedData) -> str:
        return codec.encode_signed(secret, parameters["eta"])

    def _decode_secret(self, value: Any, parameters: SerializedData) -> np.ndarray:
        return codec.decode_signed(
            value,
            "S",
            (parameters["n"], parameters["ell"]),
            parameters["eta"],
        )

    def _derive_public_key(
        self,
        parameters: SerializedData,
        product: np.ndarray,
    ) -> tuple[np.ndarray, np.ndarray]:
        q, p = parameters["q"], parameters["p"]
        public = lwr.round_q_to_p(product, q, p)
        difference = ((q // p) * public - product) % q
        error = np.where(difference > q // 2, difference - q, difference)
        return public, error

    def _lift_public_key(self, parameters: SerializedData, public: np.ndarray) -> np.ndarray:
        return (parameters["q"] // parameters["p"]) * public
