"""Fiat-Shamir-with-aborts identification from plain LWE: ``standard_lwe`` and ``binary_lwe``.

Key: B = A S + E mod q with E <- CBD_eta^{m x ell}. The two candidates differ
only in the secret: centered binomial (LWE in normal form, short secret) or
uniform binary. The proof system lives in ``lattice_zk.py``.

Default parameters (n = m = 1024, q = 8380417, eta = 2, gamma = 2^17) are sized
like CRYSTALS-Dilithium2 (the scheme itself is not Dilithium); ell = 128 with
kappa = 31 gives a 129.6-bit challenge space. They are a starting point, not a
security proof: LWE hardness (in particular with a binary secret) and the
soundness of the proof must be estimated and recorded as evidence.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from crypto_core.interface import SerializedData
from crypto_core.lwe import codec, sampling
from crypto_core.protocols.lattice_zk import common_fixed_parameters
from crypto_core.protocols.matrix_lwe_zk import MatrixLWEZKProtocol, resolve_matrix_dimensions

DEFAULT_Q = 8380417


class _SampledErrorLWEProtocol(MatrixLWEZKProtocol):
    secret_distribution = ""

    def _fixed_parameters(self) -> SerializedData:
        return {
            "secret_distribution": self.secret_distribution,
            "error_distribution": "centered_binomial",
            "matrix_distribution": "uniform_mod_q_shared",
            "key_shape": "ell_secret_columns",
            **common_fixed_parameters(),
        }

    def _resolve_tunable(self, overrides: SerializedData) -> SerializedData:
        parameters = resolve_matrix_dimensions(overrides, DEFAULT_Q)
        self._validate(parameters)
        return parameters

    def _error_bound(self, parameters: SerializedData) -> int:
        return parameters["eta"]

    def _derive_public_key(
        self,
        parameters: SerializedData,
        product: np.ndarray,
    ) -> tuple[np.ndarray, np.ndarray]:
        error = sampling.sample_centered_binomial(
            (parameters["m"], parameters["ell"]),
            parameters["eta"],
        )
        return (product + error) % parameters["q"], error


class StandardLWEProtocol(_SampledErrorLWEProtocol):
    """LWE in normal form: S and E centered binomial with parameter eta."""

    protocol_id = "standard_lwe"
    secret_distribution = "centered_binomial"

    def _secret_bound(self, parameters: SerializedData) -> int:
        return parameters["eta"]

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


class BinaryLWEProtocol(_SampledErrorLWEProtocol):
    """LWE with a uniform binary secret S in {0, 1}^{n x ell}."""

    protocol_id = "binary_lwe"
    secret_distribution = "binary"

    def _secret_bound(self, parameters: SerializedData) -> int:
        return 1

    def _sample_secret(self, parameters: SerializedData) -> np.ndarray:
        return sampling.sample_binary((parameters["n"], parameters["ell"]))

    def _encode_secret(self, secret: np.ndarray, parameters: SerializedData) -> str:
        return codec.encode_bits(secret.ravel())

    def _decode_secret(self, value: Any, parameters: SerializedData) -> np.ndarray:
        shape = (parameters["n"], parameters["ell"])
        return codec.decode_bits(value, "S", shape[0] * shape[1]).reshape(shape)
