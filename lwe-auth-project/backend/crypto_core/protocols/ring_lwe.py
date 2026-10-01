"""Fiat-Shamir-with-aborts identification from Ring-LWE (``ring_lwe``).

Ring R_q = Z_q[x] / (x^n + 1). Key: b = a s + e with a in R_q shared and
s, e <- CBD_eta. The challenge c is a polynomial with kappa coefficients in
{-1, 1} (sampled like Dilithium's SampleInBall), so one ring element already gives a
challenge space of at least 128 bits: no secret columns are needed. The proof
system lives in ``lattice_zk.py``.

Defaults (n = 1024, q = 8380417, eta = 2, kappa = 16, gamma = 2^17) are sized
like CRYSTALS-Dilithium2 (the scheme itself is not Dilithium). They are a starting point, not a
security proof, and must be estimated independently. Multiplication is
schoolbook negacyclic convolution, not an NTT.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from crypto_core.interface import SerializedData
from crypto_core.lwe import codec, ring, sampling
from crypto_core.protocols.lattice_zk import (
    MAX_MODULUS,
    Context,
    LatticeZKProtocol,
    ResponseComponent,
    common_fixed_parameters,
    field,
    require_int,
    require_mapping,
    require_power_of_two,
    validate_proof_parameters,
)

DEFAULT_N = 1024
DEFAULT_Q = 8380417
DEFAULT_ETA = 2
DEFAULT_KAPPA = 16
DEFAULT_GAMMA = 1 << 17

_MIN_N = 64
_MAX_N = 4096
_MAX_ETA = 8


def _centered(values: np.ndarray, q: int) -> np.ndarray:
    return np.where(values > q // 2, values - q, values)


class RingLWEProtocol(LatticeZKProtocol):
    """Ring-LWE with centered-binomial secret and error."""

    protocol_id = "ring_lwe"

    # -- parameters ----------------------------------------------------------------

    def _fixed_parameters(self) -> SerializedData:
        return {
            "ring": "Z_q[x]/(x^n+1)",
            "secret_distribution": "centered_binomial",
            "error_distribution": "centered_binomial",
            "polynomial_distribution": "uniform_mod_q_shared",
            "polynomial_multiplication": "schoolbook_negacyclic",
            **common_fixed_parameters(),
        }

    def _resolve_tunable(self, overrides: SerializedData) -> SerializedData:
        n = require_power_of_two(
            require_int(overrides.get("n", DEFAULT_N), "n", _MIN_N, _MAX_N),
            "n",
        )
        q = require_int(overrides.get("q", DEFAULT_Q), "q", 1 << 10, MAX_MODULUS)
        eta = require_int(overrides.get("eta", DEFAULT_ETA), "eta", 1, _MAX_ETA)
        kappa = require_int(overrides.get("kappa", DEFAULT_KAPPA), "kappa", 1, n)
        gamma = require_int(overrides.get("gamma", DEFAULT_GAMMA), "gamma", 2)
        # |c s|_inf, |c e|_inf <= kappa * eta.
        validate_proof_parameters(q, gamma, [(n, kappa * eta), (n, kappa * eta)], n, kappa)
        return {"n": n, "q": q, "eta": eta, "kappa": kappa, "gamma": gamma}

    # -- relation --------------------------------------------------------------------

    def _generate_shared(self, parameters: SerializedData) -> SerializedData:
        polynomial_a = sampling.sample_uniform_mod_q((parameters["n"],), parameters["q"])
        return {"a": codec.encode_unsigned(polynomial_a, parameters["q"])}

    def _load_shared(self, context: Context, system_parameters: SerializedData) -> np.ndarray:
        parameters = context.parameters
        _, polynomial_a = codec.decode_unsigned(
            field(system_parameters, "a", "los parámetros del sistema"),
            "a",
            (parameters["n"],),
            parameters["q"],
        )
        return polynomial_a

    def _generate_user_keys(
        self,
        context: Context,
        shared: np.ndarray,
    ) -> tuple[SerializedData, SerializedData]:
        parameters = context.parameters
        n, q, eta = parameters["n"], parameters["q"], parameters["eta"]
        secret = sampling.sample_centered_binomial((n,), eta)
        error = sampling.sample_centered_binomial((n,), eta)
        public = (ring.negacyclic_multiply(shared, secret, q) + error) % q
        return (
            {"b": codec.encode_unsigned(public, q)},
            {"s": codec.encode_signed(secret, eta), "e": codec.encode_signed(error, eta)},
        )

    def _load_public_key(
        self,
        context: Context,
        public_key: SerializedData,
    ) -> tuple[bytes, np.ndarray]:
        parameters = context.parameters
        public_key = require_mapping(public_key, "La clave pública")
        return codec.decode_unsigned(
            field(public_key, "b", "la clave pública"),
            "b",
            (parameters["n"],),
            parameters["q"],
        )

    def _load_witness(self, context: Context, private_key: dict[str, Any]) -> tuple[np.ndarray, np.ndarray]:
        parameters = context.parameters
        shape, eta = (parameters["n"],), parameters["eta"]
        secret = codec.decode_signed(field(private_key, "s", "la clave privada"), "s", shape, eta)
        error = codec.decode_signed(field(private_key, "e", "la clave privada"), "e", shape, eta)
        return secret, error

    def _response_layout(self, context: Context) -> tuple[ResponseComponent, ...]:
        parameters = context.parameters
        shape = (parameters["n"],)
        beta = parameters["kappa"] * parameters["eta"]
        return (
            ResponseComponent("z1", shape, parameters["gamma"], beta),
            ResponseComponent("z2", shape, parameters["gamma"], beta),
        )

    def _challenge_shape(self, context: Context) -> tuple[int, int]:
        return context.parameters["n"], context.parameters["kappa"]

    def _commit(
        self,
        context: Context,
        shared: np.ndarray,
        masks: tuple[np.ndarray, ...],
    ) -> np.ndarray:
        y1, y2 = masks
        q = context.parameters["q"]
        return (ring.negacyclic_multiply(shared, y1, q) + y2) % q

    def _witness_times_challenge(
        self,
        context: Context,
        witness: tuple[np.ndarray, np.ndarray],
        challenge: np.ndarray,
    ) -> tuple[np.ndarray, ...]:
        # The products are bounded by kappa * eta < q / 2, so centering mod q
        # recovers the exact integers.
        q = context.parameters["q"]
        secret, error = witness
        return (
            _centered(ring.negacyclic_multiply(challenge, secret, q), q),
            _centered(ring.negacyclic_multiply(challenge, error, q), q),
        )

    def _reconstruct_commitment(
        self,
        context: Context,
        shared: np.ndarray,
        public_material: np.ndarray,
        responses: tuple[np.ndarray, ...],
        challenge: np.ndarray,
    ) -> np.ndarray:
        z1, z2 = responses
        q = context.parameters["q"]
        return (
            ring.negacyclic_multiply(shared, z1, q)
            + z2
            - ring.negacyclic_multiply(challenge, public_material, q)
        ) % q
