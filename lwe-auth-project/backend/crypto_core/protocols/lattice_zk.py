"""Fiat-Shamir-with-aborts identification template for the lattice candidates.

``standard_lwe``, ``binary_lwe``, ``lwr`` and ``ring_lwe`` run the same proof
system; they differ only in the linear relation behind their public key.

Relation (all candidates)
    Public: shared map A (matrix or ring element) and key B with
    A S + E = B~ (mod q), where B~ is the public key lifted to Z_q.
    Witness held by the prover: short S and E (||.||_inf bounded by the key
    distribution).

Proof (Lyubashevsky 2012, LWE variant: both z1 and z2 are sent and the key has
ell secret columns; none of Dilithium's compression is used: no HighBits /
LowBits split of w, no hints, no second rejection condition, no compressed
public key. Only the parameter sizes follow Dilithium2.)
    Verifier challenge: a fresh 32-byte nonce.
    Prover:   y1, y2 <- U([-gamma, gamma])          (masks, OS CSPRNG)
              w  = A y1 + y2 mod q                  (commitment)
              c~ = H(params, H(pk), nonce, w)        (Fiat-Shamir)
              c  = SparseTernary(c~)                 (||c||_1 = kappa)
              z1 = y1 + S c,  z2 = y2 + E c
              restart unless ||z_i||_inf <= gamma - beta_i, beta_i = kappa * ||witness_i||_inf
              response = (c~, z1, z2)
    Verifier: checks the norm bounds, recomputes w' = A z1 + z2 - B~ c mod q
              and accepts iff H(params, H(pk), nonce, w') = c~.

Properties (stated precisely; nothing beyond this is claimed)
    * Zero knowledge: the underlying interactive protocol is non-abort
      special honest-verifier zero knowledge. Its Fiat-Shamir version is a
      NIZK in the programmable random-oracle model: the simulator samples c~,
      derives c, samples z uniformly on [-(gamma - beta), gamma - beta], sets
      w = A z1 + z2 - B~ c and programs H(params, H(pk), nonce, w) = c~. This
      matches real transcripts because ||witness * c||_inf <= beta, so an
      accepted z is uniform on that box whatever the witness, and the
      acceptance probability per attempt depends only on (gamma, beta,
      dimensions), never on the witness. Aborted attempts are never sent.
      Not analysed: the quantum random-oracle model, timing side channels.
    * Argument of knowledge for a RELAXED relation, not for (S, E) itself:
      two accepting transcripts with the same w and c != c' give short
      (z1 - z1', z2 - z2', c - c') with A (z1 - z1') + (z2 - z2') = B~ (c - c')
      (mod q). Impersonation security therefore rests on the key being
      pseudorandom (LWE / Ring-LWE / LWR) plus SIS hardness of [A | I | -B~]
      at norm 2 (gamma - beta), both to be estimated for the parameters used.
    * Freshness and binding: the nonce and H(pk) are hashed into c~, so a
      response does not verify under another challenge or another public key.
    * The proof is non-interactive, hence transferable: unlike the previous
      encryption-based protocol it is not deniable.
    * Verification is stateless; the verifier only has to remember which
      nonces it issued to prevent replay across sessions.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import secrets
from dataclasses import dataclass
from typing import Any

import numpy as np

from crypto_core.exceptions import CryptoCoreError, InvalidProtocolDataError
from crypto_core.interface import AuthProtocol, KeyPair, SerializedData
from crypto_core.lwe import codec, sampling

_DOMAIN = b"lwe-auth/fiat-shamir-with-aborts/v1"
NONCE_BYTES = 32
DIGEST_BYTES = 32
MAX_MODULUS = 1 << 24
MIN_CHALLENGE_SPACE_BITS = 128
MIN_ACCEPTANCE_PROBABILITY = 0.05
# The commitment must stay far from q so short-vector forgery remains hard.
MIN_MODULUS_TO_GAMMA_RATIO = 16
MAX_PROOF_ATTEMPTS = 1000


def common_fixed_parameters() -> SerializedData:
    return {
        "proof_system": "fiat_shamir_with_aborts",
        "challenge_distribution": "sparse_ternary_shake256",
        "masking_distribution": "uniform_box",
        "nonce_bytes": NONCE_BYTES,
        "hash": "sha3-256",
        "xof": "shake256",
        "coefficient_encoding": "minimal_width_le_base64",
    }


def require_int(value: Any, name: str, minimum: int, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidProtocolDataError(f"'{name}' debe ser un entero.")
    if value < minimum:
        raise InvalidProtocolDataError(f"'{name}' debe ser al menos {minimum}.")
    if maximum is not None and value > maximum:
        raise InvalidProtocolDataError(f"'{name}' no puede superar {maximum}.")
    return value


def require_power_of_two(value: int, name: str) -> int:
    if value & (value - 1):
        raise InvalidProtocolDataError(f"'{name}' debe ser una potencia de 2.")
    return value


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InvalidProtocolDataError(f"{label} debe ser un objeto JSON.")
    return value


def field(container: dict[str, Any], key: str, label: str) -> Any:
    try:
        return container[key]
    except KeyError as exc:
        raise InvalidProtocolDataError(f"Falta '{key}' en {label}.") from exc


def challenge_space_bits(length: int, weight: int) -> float:
    """log2 of the number of vectors in {-1,0,1}^length with ``weight`` nonzeros."""
    combinations = (
        math.lgamma(length + 1) - math.lgamma(weight + 1) - math.lgamma(length - weight + 1)
    )
    return combinations / math.log(2) + weight


def validate_proof_parameters(
    q: int,
    gamma: int,
    components: list[tuple[int, int]],
    challenge_length: int,
    challenge_weight: int,
) -> None:
    """Reject parameter sets that break soundness, zero knowledge or termination.

    ``components`` lists (dimension, beta) for every response vector.
    """
    if not 0 < challenge_weight <= challenge_length:
        raise InvalidProtocolDataError("'kappa' debe estar entre 1 y la longitud del desafío.")
    if challenge_space_bits(challenge_length, challenge_weight) < MIN_CHALLENGE_SPACE_BITS:
        raise InvalidProtocolDataError(
            f"El espacio de desafíos debe tener al menos {MIN_CHALLENGE_SPACE_BITS} bits."
        )
    if MIN_MODULUS_TO_GAMMA_RATIO * gamma > q:
        raise InvalidProtocolDataError(
            f"'gamma' debe ser como máximo q / {MIN_MODULUS_TO_GAMMA_RATIO}."
        )
    acceptance = 1.0
    for dimension, beta in components:
        if beta >= gamma:
            raise InvalidProtocolDataError(
                "'gamma' debe superar kappa * norma del testigo; la prueba no ocultaría el secreto."
            )
        acceptance *= ((2 * (gamma - beta) + 1) / (2 * gamma + 1)) ** dimension
    if acceptance < MIN_ACCEPTANCE_PROBABILITY:
        raise InvalidProtocolDataError(
            f"Probabilidad de aceptación por intento {acceptance:.3g} < "
            f"{MIN_ACCEPTANCE_PROBABILITY}; aumente 'gamma' o reduzca 'kappa'."
        )


def _digest(*parts: bytes) -> bytes:
    """SHA3-256 over length-prefixed fields (unambiguous concatenation)."""
    hasher = hashlib.sha3_256()
    for part in parts:
        hasher.update(len(part).to_bytes(8, "big"))
        hasher.update(part)
    return hasher.digest()


@dataclass(frozen=True, slots=True)
class Context:
    parameters: SerializedData
    parameters_digest: bytes


@dataclass(frozen=True, slots=True)
class ResponseComponent:
    """One response vector z = y + (witness * c), masked with y in [-gamma, gamma]."""

    name: str
    shape: tuple[int, ...]
    gamma: int
    beta: int

    @property
    def bound(self) -> int:
        return self.gamma - self.beta


class LatticeZKProtocol(AuthProtocol):
    """Implements the common lifecycle; subclasses define the linear relation."""

    protocol_id = ""

    @property
    def name(self) -> str:
        return self.protocol_id

    # -- relation hooks --------------------------------------------------------------

    def _fixed_parameters(self) -> SerializedData:
        raise NotImplementedError

    def _resolve_tunable(self, overrides: SerializedData) -> SerializedData:
        """Validate tunable overrides and return every tunable effective value."""
        raise NotImplementedError

    def _generate_shared(self, parameters: SerializedData) -> SerializedData:
        raise NotImplementedError

    def _load_shared(self, context: Context, system_parameters: SerializedData) -> Any:
        raise NotImplementedError

    def _generate_user_keys(
        self,
        context: Context,
        shared: Any,
    ) -> tuple[SerializedData, SerializedData]:
        """Return (public key fields, private witness fields)."""
        raise NotImplementedError

    def _load_public_key(
        self,
        context: Context,
        public_key: SerializedData,
    ) -> tuple[bytes, Any]:
        """Return (canonical public bytes, public key lifted to Z_q)."""
        raise NotImplementedError

    def _load_witness(self, context: Context, private_key: dict[str, Any]) -> Any:
        raise NotImplementedError

    def _response_layout(self, context: Context) -> tuple[ResponseComponent, ...]:
        raise NotImplementedError

    def _challenge_shape(self, context: Context) -> tuple[int, int]:
        """Return (challenge length, number of nonzero coefficients)."""
        raise NotImplementedError

    def _commit(self, context: Context, shared: Any, masks: tuple[np.ndarray, ...]) -> np.ndarray:
        """Return A y mod q."""
        raise NotImplementedError

    def _witness_times_challenge(
        self,
        context: Context,
        witness: Any,
        challenge: np.ndarray,
    ) -> tuple[np.ndarray, ...]:
        """Return the exact integer products (S c, E c)."""
        raise NotImplementedError

    def _reconstruct_commitment(
        self,
        context: Context,
        shared: Any,
        public_material: Any,
        responses: tuple[np.ndarray, ...],
        challenge: np.ndarray,
    ) -> np.ndarray:
        """Return A z - B~ c mod q."""
        raise NotImplementedError

    # -- parameters ----------------------------------------------------------------

    def default_parameters(self) -> SerializedData:
        return {**self._resolve_tunable({}), **self._fixed_parameters()}

    def resolve_parameters(
        self, overrides: SerializedData | None = None
    ) -> SerializedData:
        overrides = require_mapping(
            {} if overrides is None else overrides,
            "Los parámetros",
        )
        fixed = self._fixed_parameters()
        known = set(fixed) | set(self._resolve_tunable({}))
        unknown = set(overrides) - known
        if unknown:
            raise InvalidProtocolDataError(
                f"Parámetros {self.protocol_id} desconocidos: {sorted(unknown)}."
            )
        for key, expected in fixed.items():
            if key in overrides and overrides[key] != expected:
                raise InvalidProtocolDataError(
                    f"'{key}' está fijado a {expected!r} en {self.protocol_id}."
                )
        tunable = self._resolve_tunable(
            {key: value for key, value in overrides.items() if key not in fixed}
        )
        return {**tunable, **fixed}

    def _context(self, system_parameters: SerializedData) -> Context:
        system_parameters = require_mapping(
            system_parameters,
            "Los parámetros del sistema",
        )
        protocol = field(system_parameters, "protocol", "los parámetros del sistema")
        if protocol != self.protocol_id:
            raise InvalidProtocolDataError(
                f"Los parámetros del sistema pertenecen a '{protocol}', "
                f"no a '{self.protocol_id}'."
            )
        parameters = require_mapping(
            field(system_parameters, "parameters", "los parámetros del sistema"),
            "'parameters'",
        )
        if self.resolve_parameters(parameters) != parameters:
            raise InvalidProtocolDataError(
                "Los parámetros del sistema no son el conjunto efectivo completo."
            )
        canonical = json.dumps(parameters, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return Context(
            parameters=parameters,
            parameters_digest=_digest(_DOMAIN, b"parameters", canonical),
        )

    # -- Fiat-Shamir -----------------------------------------------------------------

    def _public_key_digest(self, context: Context, public_raw: bytes) -> bytes:
        return _digest(
            _DOMAIN,
            b"public-key",
            self.protocol_id.encode("ascii"),
            context.parameters_digest,
            public_raw,
        )

    def _challenge_seed(
        self,
        context: Context,
        public_key_digest: bytes,
        nonce: bytes,
        commitment: np.ndarray,
    ) -> bytes:
        q = context.parameters["q"]
        return _digest(
            _DOMAIN,
            b"challenge",
            self.protocol_id.encode("ascii"),
            context.parameters_digest,
            public_key_digest,
            nonce,
            codec.unsigned_bytes(commitment, q),
        )

    def _challenge(self, context: Context, seed: bytes) -> np.ndarray:
        length, weight = self._challenge_shape(context)
        return sampling.derive_sparse_ternary(seed, length, weight)

    @staticmethod
    def _parse_nonce(challenge: SerializedData) -> bytes:
        challenge = require_mapping(challenge, "El desafío")
        return codec.decode_fixed_bytes(
            field(challenge, "nonce", "el desafío"),
            "nonce",
            NONCE_BYTES,
        )

    # -- AuthProtocol --------------------------------------------------------------

    def generate_system_parameters(self, **params: Any) -> SerializedData:
        parameters = self.resolve_parameters(params)
        return {
            "protocol": self.protocol_id,
            "parameters": parameters,
            **self._generate_shared(parameters),
        }

    def generate_keypair(
        self,
        system_parameters: SerializedData,
        **params: Any,
    ) -> KeyPair:
        context = self._context(system_parameters)
        if self.resolve_parameters(params) != context.parameters:
            raise InvalidProtocolDataError(
                "Los parámetros de enrollment no coinciden con los del setup."
            )
        public_key, witness = self._generate_user_keys(
            context,
            self._load_shared(context, system_parameters),
        )
        public_raw, _ = self._load_public_key(context, public_key)
        private_key = {
            **witness,
            "public_key_digest": codec.encode_bytes(
                self._public_key_digest(context, public_raw)
            ),
        }
        return public_key, private_key

    def generate_challenge(
        self,
        system_parameters: SerializedData,
        public_key: SerializedData,
    ) -> SerializedData:
        # The proof binds H(pk) itself; the nonce only has to be fresh.
        self._context(system_parameters)
        del public_key
        return {"nonce": codec.encode_bytes(secrets.token_bytes(NONCE_BYTES))}

    def solve_challenge(
        self,
        system_parameters: SerializedData,
        private_key: SerializedData,
        challenge: SerializedData,
    ) -> SerializedData:
        context = self._context(system_parameters)
        private_key = require_mapping(private_key, "La clave privada")
        witness = self._load_witness(context, private_key)
        public_key_digest = codec.decode_fixed_bytes(
            field(private_key, "public_key_digest", "la clave privada"),
            "public_key_digest",
            DIGEST_BYTES,
        )
        nonce = self._parse_nonce(challenge)
        shared = self._load_shared(context, system_parameters)
        layout = self._response_layout(context)

        for _ in range(MAX_PROOF_ATTEMPTS):
            masks = tuple(
                sampling.sample_uniform_box(component.shape, component.gamma)
                for component in layout
            )
            commitment = self._commit(context, shared, masks)
            seed = self._challenge_seed(context, public_key_digest, nonce, commitment)
            products = self._witness_times_challenge(
                context,
                witness,
                self._challenge(context, seed),
            )
            responses = tuple(mask + product for mask, product in zip(masks, products))
            if all(
                int(np.abs(response).max()) <= component.bound
                for response, component in zip(responses, layout)
            ):
                return {
                    "c": codec.encode_bytes(seed),
                    **{
                        component.name: codec.encode_signed(response, component.bound)
                        for component, response in zip(layout, responses)
                    },
                }
        raise CryptoCoreError(
            "La prueba no terminó tras el máximo de intentos de rejection sampling."
        )

    def verify_response(
        self,
        system_parameters: SerializedData,
        public_key: SerializedData,
        challenge: SerializedData,
        response: SerializedData,
    ) -> bool:
        context = self._context(system_parameters)
        public_raw, public_material = self._load_public_key(context, public_key)
        nonce = self._parse_nonce(challenge)
        response = require_mapping(response, "La respuesta")
        seed = codec.decode_fixed_bytes(
            field(response, "c", "la respuesta"),
            "c",
            DIGEST_BYTES,
        )
        # decode_signed rejects any coefficient above the bound: this is the norm check.
        responses = tuple(
            codec.decode_signed(
                field(response, component.name, "la respuesta"),
                component.name,
                component.shape,
                component.bound,
            )
            for component in self._response_layout(context)
        )
        commitment = self._reconstruct_commitment(
            context,
            self._load_shared(context, system_parameters),
            public_material,
            responses,
            self._challenge(context, seed),
        )
        expected = self._challenge_seed(
            context,
            self._public_key_digest(context, public_raw),
            nonce,
            commitment,
        )
        return hmac.compare_digest(expected, seed)
