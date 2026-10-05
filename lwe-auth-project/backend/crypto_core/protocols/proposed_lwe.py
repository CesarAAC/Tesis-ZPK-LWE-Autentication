"""PQLite-Auth v2 (``proposed_lwe``), the protocol proposed by the thesis, in its
dual-modulus form.

Cryptographic sources of truth
    1. ``Document/capitulos/04-Protocolo Propio.tex``. Comments of the form
       ``tex:N-M`` point to the lines of that file this code implements (as of
       the version the implementation was written against).
    2. The authors' "dual modulus" instruction (their Option A), which replaces
       the proof of that chapter: Fiat-Shamir with aborts over a second modulus
       q' = 8380417 with the HighBits / LowBits decomposition and the rejection
       sampling of Lyubashevsky and Dilithium, while q = 3329 stays for the
       token hiding and the session-key agreement. Where the chapter and the
       instruction differ, the instruction wins and the difference is listed
       below.

Two layers
    Proof layer      R_q' = Z_q'[x] / (x^d + 1), q' = 8380417. Identity key and proof.
    Transport layer  q = 3329. ML-KEM-768 (token hiding) and the key agreement
                     over R_q = Z_q[x] / (x^d + 1) with Peikert reconciliation.

Flow
    Setup       rho <- 32 random bytes; verifier ML-KEM-768 key pair (vpk, vsk).
                A' in R_q'^{k' x k'} and A in R_q^{k x k} are SHAKE-128
                expansions of rho under different seeds. system_parameters =
                {rho, vpk}; vsk stays in the process keystore.
    Enrollment  s, e <- CBD(eta)^k', t = A' s + e mod q'. Public key t;
                private key (s, e) plus H(t).
    Challenge   the verifier issues a single-use ticket (256 bits) and the
                timestamp nu.
    Response    y  <- uniform on [-(gamma1 - 1), gamma1 - 1]^(k' d)
                w  = A' y mod q',  w1 = HighBits(w, 2 gamma2)
                c~ = H(A', t, w1, ticket, nu),  c = SampleInBall(c~)
                z  = y + c s
                restart unless ||z||_inf < gamma1 - beta
                           and ||LowBits(w - c e, 2 gamma2)||_inf < gamma2 - beta
                tok1 = ML-KEM-768 ciphertext, tok2 = AES-256-GCM_K(z, c~, ticket, nu).
    Verify      decrypt, time window, spent-ticket log, ||z||_inf < gamma1 - beta,
                w1' = HighBits(A' z - c t, 2 gamma2), accept iff
                H(A', t, w1', ticket, nu) = c~.
    Session key ``generate_reconciliation_hint`` / ``reconcile_session_key``
                (Peikert reconciliation over q), outside the ``AuthProtocol``
                contract.

Why an honest proof always verifies
    A' z - c t = A' y + c A' s - c (A' s + e) = w - c e. With beta = eta * kappa,
    ||c e||_inf <= beta, and the prover only releases z when
    ||LowBits(w - c e)||_inf < gamma2 - beta, so adding c e back does not change
    the high bits: HighBits(w - c e) = HighBits(w) = w1 and the verifier hashes
    the same input. There is no completeness error: the only randomness is in
    how many attempts the prover needs.

What each source leaves open, and the reading taken
    Each one is an open value or a deviation, not a silent correction; the
    README lists them and the tests in ``ManuscriptDeviationTests`` show why.

    1. Rank of the proof layer, ``k_proof``. The manuscript fixes k = 3 for
       q = 3329; the instruction changes the modulus of the proof and says
       nothing about its rank. The authors chose 4 on 2026-10-04 (dimension
       1024, as ML-DSA-44); 3, the manuscript's k, stays available. Hardness
       of t = A' s + e depends on it: see "Security status".
    2. Scalar challenge. The manuscript takes L = H(...) in R_q^{k x k} and
       z = s L + y. Its cancellation A (s L) - (A s + e) L = -e L needs
       A L = L A, which a hashed matrix does not satisfy. The challenge is the
       scalar matrix L = c I, with c a short ring element.
    3. Challenge distribution. c has ``kappa`` coefficients in {-1, 1} and the
       rest zero (default 23, the smallest weight giving at least 2^128
       challenges for d = 256), so beta = eta * kappa bounds c s and c e.
    4. ``gamma1`` and ``gamma2``. Neither source gives them. The defaults are
       ML-DSA-44's, 2^17 and (q' - 1) / 88, the values Dilithium defines for
       this modulus.
    5. The manuscript's mask y <- CBD(eta), its bounds beta_z and beta_e and the
       check ||A z - t L - w||_inf <= beta_e are replaced by the uniform mask,
       the two rejection conditions and the high-bits check above. The
       commitment w no longer travels in the token.
    6. ``time_window_seconds`` (the manuscript's Delta t) defaults to 300.
    7. The ticket and nu are issued by the verifier in ``generate_challenge``;
       the contract needs a verifier challenge and the manuscript does not say
       who creates the ticket. The token must carry exactly that pair.
    8. tok1 is an ML-KEM-768 encapsulation and K the encapsulated secret,
       instead of Kyber.Enc(vpk, K) for a client-chosen K.
    9. rec is Peikert's function as defined by the cited source. The closed
       formula printed in the manuscript equals (floor(2 w / q) - v) mod 2,
       which tolerates no error at all.
    10. Key-agreement shares. The manuscript uses b_C, b_S, s_S, e_S and s_C
        without defining them or saying how they travel. Following the cited
        source, ``generate_key_agreement_share`` builds b = A s + e (client)
        and b = A^T s + e (server); exchanging them is left to the caller.

Security status (stated precisely; nothing beyond this is claimed)
    * The proof is Dilithium's template without public-key compression
      (Figure 1 of its round-3 specification: no Power2Round, no hints), with a
      square matrix, CBD(eta) secrets and (ticket, nu) in the place of the
      message. It is a NIZK in the programmable random-oracle model: the
      simulator samples c~, derives c, samples z uniformly with
      ||z||_inf < gamma1 - beta, restarts unless
      ||LowBits(A' z - c t)||_inf < gamma2 - beta, and programs
      H(A', t, HighBits(A' z - c t), ticket, nu) = c~. Real transcripts have
      that distribution because ||c s||_inf <= beta makes an accepted z uniform
      on its box whatever s is, and the second condition is a function of
      (z, c, t) alone. The designated verifier sees exactly (z, c~), so this
      covers it as well. Aborted attempts are never released.
    * It is an argument of knowledge for a RELAXED relation: two accepting
      transcripts with the same w1 and c != c' give short (z - z', u, c - c')
      with A' (z - z') + u = (c - c') t. Impersonation security therefore
      rests on MLWE (t pseudorandom) and on MSIS for [A' | I | t], at the rank
      and modulus of the proof layer.
    * Those hardness assumptions must be estimated for the parameters in use;
      the protocol does not do it (``benchmarking.hardness`` does, with the
      lattice estimator). With the default rank 4 the key is an instance of
      dimension 1024 at a 23-bit modulus, near 2^115 classical operations in
      the Core-SVP model; with rank 3 it drops to about 2^79, below the
      level of ML-KEM-768 (dimension 768 at q = 3329). The README gives the
      figures per rank.
    * Not analysed: the quantum random-oracle model and side channels. The
      number of prover attempts shows in its running time, and its distribution
      does not depend on the key; NumPy arithmetic is not constant time;
      products are schoolbook, not NTT.
    * Once decrypted, (z, c~) is a publicly verifiable proof for (ticket, nu):
      the verifier can show it to third parties. Token hiding restricts who
      can read the proof, not who can check it.
    * Parties other than the verifier see only the token, protected by
      ML-KEM-768 and AES-256-GCM.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from crypto_core import token_hiding
from crypto_core.exceptions import CryptoCoreError, InvalidProtocolDataError
from crypto_core.interface import AuthProtocol, KeyPair, SerializedData
from crypto_core.lwe import codec, decomposition, module, reconciliation, sampling

PROTOCOL_ID = "proposed_lwe"
_DOMAIN = b"lwe-auth/pqlite-auth-v2/dual-modulus/v1"

# Parameter vector fixed by the manuscript (tex:40-42). q is the transport-layer modulus.
DEGREE = 256
RANK = 3
MODULUS = 3329
ETA = 2

# Proof-layer modulus fixed by the dual-modulus instruction (the ML-DSA prime, 23 bits).
PROOF_MODULUS = 8_380_417

# Values neither source fixes (readings 1, 3, 4 and 6 above).
DEFAULT_PROOF_RANK = 4
DEFAULT_KAPPA = 23
DEFAULT_GAMMA1 = 1 << 17
DEFAULT_GAMMA2 = (PROOF_MODULUS - 1) // 88
DEFAULT_TIME_WINDOW_SECONDS = 300

SEED_BYTES = 32
TICKET_BYTES = 32
TIMESTAMP_BYTES = 8
DIGEST_BYTES = 32
HINT_BYTES = DEGREE // 8
MAX_PROOF_RANK = 8
MIN_CHALLENGE_SPACE_BITS = 128
MIN_ACCEPTANCE_PROBABILITY = 0.05
# Sanity limits, gamma1 <= q' / 8 and at least 16 high values, that still admit the
# largest ML-DSA choices (gamma1 = 2^19, gamma2 = (q' - 1) / 32).
MIN_MODULUS_TO_GAMMA1_RATIO = 8
MIN_HIGH_VALUES = 16
MAX_PROOF_ATTEMPTS = 1000

_TUNABLE = ("k_proof", "kappa", "gamma1", "gamma2", "time_window_seconds")
_MAX_TIME_WINDOW_SECONDS = 86_400
_MAX_TIMESTAMP = (1 << (8 * TIMESTAMP_BYTES - 1)) - 1
_SECRET_RANGE = 2 * ETA + 1
_KEYSTORE_CAPACITY = 65_536
_SPENT_LOG_PRUNE_SIZE = 8_192


def _fixed_parameters() -> SerializedData:
    return {
        "d": DEGREE,
        "k": RANK,
        "q": MODULUS,
        "eta": ETA,
        "q_proof": PROOF_MODULUS,
        "ring": "Z_q[x]/(x^d+1)",
        "noise_distribution": "centered_binomial",
        "matrix_expansion": "shake128_from_seed",
        "proof_system": "fiat_shamir_with_aborts_high_bits",
        "masking_distribution": "uniform_box",
        "challenge_distribution": "scalar_sparse_ternary_shake256",
        "hash": "sha3-256",
        "kem": "ML-KEM-768",
        "aead": "AES-256-GCM",
        "coefficient_encoding": "bit_packed_base64",
        "ticket_bytes": TICKET_BYTES,
        "reconciliation": "peikert_cross_rounding_odd_modulus",
    }


def _require_int(value: Any, name: str, minimum: int, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidProtocolDataError(f"'{name}' debe ser un entero.")
    if value < minimum:
        raise InvalidProtocolDataError(f"'{name}' debe ser al menos {minimum}.")
    if maximum is not None and value > maximum:
        raise InvalidProtocolDataError(f"'{name}' no puede superar {maximum}.")
    return value


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InvalidProtocolDataError(f"{label} debe ser un objeto JSON.")
    return value


def _field(container: dict[str, Any], key: str, label: str) -> Any:
    try:
        return container[key]
    except KeyError as exc:
        raise InvalidProtocolDataError(f"Falta '{key}' en {label}.") from exc


def _digest(*parts: bytes) -> bytes:
    """SHA3-256 over length-prefixed fields (unambiguous concatenation)."""
    hasher = hashlib.sha3_256()
    for part in parts:
        hasher.update(len(part).to_bytes(8, "big"))
        hasher.update(part)
    return hasher.digest()


def challenge_space_bits(degree: int, weight: int) -> float:
    """log2 of the number of polynomials with ``weight`` coefficients in {-1, 1}."""
    combinations = (
        math.lgamma(degree + 1) - math.lgamma(weight + 1) - math.lgamma(degree - weight + 1)
    )
    return combinations / math.log(2) + weight


def acceptance_probability(proof_rank: int, gamma1: int, gamma2: int, beta: int) -> float:
    """Probability that one prover attempt passes both rejection conditions.

    The response factor does not depend on the key: whatever c s is, as long as
    ||c s||_inf <= beta, the same number of masks leads to an accepted z. The
    low-bits factor treats the coefficients of w - c e as uniform in Z_q'.
    """
    response = (2 * (gamma1 - beta) - 1) / (2 * gamma1 - 1)
    low_bits = (2 * (gamma2 - beta) - 1) / (2 * gamma2)
    return (response * low_bits) ** (proof_rank * DEGREE)


@dataclass(frozen=True, slots=True)
class _Context:
    parameters: SerializedData
    parameters_digest: bytes
    rho: bytes
    verifier_public_key: bytes
    verifier_key_id: bytes

    @property
    def proof_shape(self) -> tuple[int, int]:
        return self.parameters["k_proof"], DEGREE

    @property
    def response_bound(self) -> int:
        """Released responses satisfy ||z||_inf < gamma1 - beta."""
        return self.parameters["gamma1"] - self.parameters["beta"]

    @property
    def rounding_step(self) -> int:
        """alpha = 2 gamma2, the step of the HighBits / LowBits decomposition."""
        return 2 * self.parameters["gamma2"]

    @property
    def response_bytes(self) -> int:
        count = self.parameters["k_proof"] * DEGREE
        return codec.packed_length(count, 2 * self.parameters["gamma1"])

    @property
    def payload_bytes(self) -> int:
        return self.response_bytes + DIGEST_BYTES + TICKET_BYTES + TIMESTAMP_BYTES


@dataclass(frozen=True, slots=True)
class _OpenedToken:
    response: np.ndarray
    challenge_seed: bytes
    ticket: bytes
    nu: int


@dataclass(slots=True)
class _VerifierState:
    """Secret state of one designated verifier: decryption key and ticket logs."""

    private_seed: bytes
    lock: threading.Lock = field(default_factory=threading.Lock)
    spent: dict[bytes, int] = field(default_factory=dict)
    authenticated: dict[bytes, int] = field(default_factory=dict)
    _private_key: Any = None

    def private_key(self) -> Any:
        if self._private_key is None:
            self._private_key = token_hiding.load_private_key(self.private_seed)
        return self._private_key


class _VerifierKeystore:
    """Process-local custody of verifier state, keyed by H(vpk).

    ``system_parameters`` is public by contract and the registry builds a new
    protocol object per call, so the verifier's secrets (vsk and the spent-ticket
    log) cannot live in either. They stay in the memory of the process that ran
    setup: a deployment with several worker processes would need a shared store.
    The least recently used verifiers are dropped beyond ``capacity``.
    """

    def __init__(self, capacity: int) -> None:
        self._capacity = capacity
        self._states: OrderedDict[bytes, _VerifierState] = OrderedDict()
        self._lock = threading.Lock()

    def register(self, key_id: bytes, private_seed: bytes) -> None:
        with self._lock:
            self._states[key_id] = _VerifierState(private_seed)
            while len(self._states) > self._capacity:
                self._states.popitem(last=False)

    def get(self, key_id: bytes) -> _VerifierState:
        with self._lock:
            state = self._states.get(key_id)
            if state is None:
                raise InvalidProtocolDataError(
                    "Este proceso no custodia la clave privada del verificador (vsk) "
                    "correspondiente a estos parámetros del sistema."
                )
            self._states.move_to_end(key_id)
            return state


_KEYSTORE = _VerifierKeystore(_KEYSTORE_CAPACITY)


class ProposedLWEAuthProtocol(AuthProtocol):
    """PQLite-Auth v2 mapped onto the common ``AuthProtocol`` lifecycle."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        # Injectable so the time-window check can be tested without sleeping.
        self._clock = clock

    @property
    def name(self) -> str:
        return PROTOCOL_ID

    # -- parameters ----------------------------------------------------------------

    def default_parameters(self) -> SerializedData:
        return self.resolve_parameters({})

    def resolve_parameters(
        self, overrides: SerializedData | None = None
    ) -> SerializedData:
        overrides = _require_mapping(
            {} if overrides is None else overrides,
            "Los parámetros",
        )
        fixed = _fixed_parameters()
        unknown = set(overrides) - set(fixed) - set(_TUNABLE) - {"beta"}
        if unknown:
            raise InvalidProtocolDataError(
                f"Parámetros {PROTOCOL_ID} desconocidos: {sorted(unknown)}."
            )
        for key, expected in fixed.items():
            if key in overrides and (
                type(overrides[key]) is not type(expected) or overrides[key] != expected
            ):
                raise InvalidProtocolDataError(
                    f"'{key}' está fijado a {expected!r} en PQLite-Auth v2."
                )

        proof_rank = _require_int(
            overrides.get("k_proof", DEFAULT_PROOF_RANK), "k_proof", RANK, MAX_PROOF_RANK
        )
        kappa = _require_int(overrides.get("kappa", DEFAULT_KAPPA), "kappa", 1, DEGREE)
        if challenge_space_bits(DEGREE, kappa) < MIN_CHALLENGE_SPACE_BITS:
            raise InvalidProtocolDataError(
                f"El espacio de desafíos debe tener al menos {MIN_CHALLENGE_SPACE_BITS} bits."
            )
        # Largest value ||c s||_inf and ||c e||_inf can take: derived, not tunable.
        beta = ETA * kappa
        if "beta" in overrides and (
            type(overrides["beta"]) is not int or overrides["beta"] != beta
        ):
            raise InvalidProtocolDataError(
                f"'beta' no es ajustable: vale eta * kappa = {beta}."
            )
        gamma1 = _require_int(
            overrides.get("gamma1", DEFAULT_GAMMA1),
            "gamma1",
            beta + 1,
            PROOF_MODULUS // MIN_MODULUS_TO_GAMMA1_RATIO,
        )
        gamma2 = _require_int(
            overrides.get("gamma2", DEFAULT_GAMMA2),
            "gamma2",
            beta + 1,
            (PROOF_MODULUS - 1) // (2 * MIN_HIGH_VALUES),
        )
        if (PROOF_MODULUS - 1) % (2 * gamma2):
            raise InvalidProtocolDataError(
                "'gamma2' debe cumplir que 2 * gamma2 divida a q_proof - 1; de lo "
                "contrario la descomposición en bits altos y bajos no está definida."
            )
        acceptance = acceptance_probability(proof_rank, gamma1, gamma2, beta)
        if acceptance < MIN_ACCEPTANCE_PROBABILITY:
            raise InvalidProtocolDataError(
                f"Probabilidad de aceptación por intento {acceptance:.3g} < "
                f"{MIN_ACCEPTANCE_PROBABILITY}; aumente 'gamma1' o 'gamma2', o reduzca 'kappa'."
            )
        time_window = _require_int(
            overrides.get("time_window_seconds", DEFAULT_TIME_WINDOW_SECONDS),
            "time_window_seconds",
            1,
            _MAX_TIME_WINDOW_SECONDS,
        )
        return {
            **fixed,
            "k_proof": proof_rank,
            "kappa": kappa,
            "beta": beta,
            "gamma1": gamma1,
            "gamma2": gamma2,
            "time_window_seconds": time_window,
        }

    def _context(self, system_parameters: SerializedData) -> _Context:
        label = "los parámetros del sistema"
        system_parameters = _require_mapping(system_parameters, "Los parámetros del sistema")
        protocol = _field(system_parameters, "protocol", label)
        if protocol != PROTOCOL_ID:
            raise InvalidProtocolDataError(
                f"Los parámetros del sistema pertenecen a '{protocol}', no a '{PROTOCOL_ID}'."
            )
        given = _require_mapping(_field(system_parameters, "parameters", label), "'parameters'")
        parameters = self.resolve_parameters(given)
        if parameters != given:
            raise InvalidProtocolDataError(
                "Los parámetros del sistema no son el conjunto efectivo completo."
            )
        rho = codec.decode_fixed_bytes(_field(system_parameters, "rho", label), "rho", SEED_BYTES)
        verifier_public_key = codec.decode_fixed_bytes(
            _field(system_parameters, "vpk", label),
            "vpk",
            token_hiding.PUBLIC_KEY_BYTES,
        )
        canonical = json.dumps(parameters, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return _Context(
            parameters=parameters,
            parameters_digest=_digest(_DOMAIN, b"parameters", canonical),
            rho=rho,
            verifier_public_key=verifier_public_key,
            verifier_key_id=_digest(_DOMAIN, b"verifier-key", verifier_public_key),
        )

    # -- shared building blocks ------------------------------------------------------

    @staticmethod
    def _proof_matrix(context: _Context) -> tuple[np.ndarray, bytes]:
        """Expand A' in R_q'^{k' x k'} and return it with the digest hashed into c~.

        Its seed is derived from rho so that A' and the transport-layer matrix A
        come from unrelated SHAKE-128 streams.
        """
        rank = context.parameters["k_proof"]
        seed = _digest(_DOMAIN, b"proof-matrix-seed", context.rho)
        matrix = module.expand_uniform_matrix(seed, rank, rank, DEGREE, PROOF_MODULUS)
        return matrix, _digest(
            _DOMAIN, b"matrix", codec.pack_coefficients(matrix, PROOF_MODULUS)
        )

    @staticmethod
    def _agreement_matrix(context: _Context) -> np.ndarray:
        """Expand A in R_q^{k x k} from rho (tex:322), the matrix of the key agreement."""
        return module.expand_uniform_matrix(context.rho, RANK, RANK, DEGREE, MODULUS)

    @staticmethod
    def _public_vector(context: _Context, public_key: SerializedData) -> tuple[bytes, np.ndarray]:
        """Return (H(t), t) for a public key, t in R_q'^k' at 23 bits per coefficient."""
        public_key = _require_mapping(public_key, "La clave pública")
        raw, vector = codec.decode_packed(
            _field(public_key, "t", "la clave pública"),
            "t",
            context.proof_shape,
            PROOF_MODULUS,
        )
        return _digest(_DOMAIN, b"public-key", raw), vector

    @staticmethod
    def _witness(
        context: _Context,
        private_key: SerializedData,
    ) -> tuple[np.ndarray, np.ndarray, bytes]:
        """Return (s, e, H(t)); s and e are stored as eta + value at 3 bits each."""
        label = "la clave privada"
        private_key = _require_mapping(private_key, "La clave privada")
        vectors = []
        for name in ("s", "e"):
            # Offsets above 2 eta are rejected by the decoder: this is the CBD range check.
            _, offsets = codec.decode_packed(
                _field(private_key, name, label), name, context.proof_shape, _SECRET_RANGE
            )
            vectors.append(offsets - ETA)
        public_key_digest = codec.decode_fixed_bytes(
            _field(private_key, "public_key_digest", label),
            "public_key_digest",
            DIGEST_BYTES,
        )
        return vectors[0], vectors[1], public_key_digest

    @staticmethod
    def _small_vector(container: SerializedData, label: str) -> np.ndarray:
        """Decode a key-agreement CBD(eta) vector stored mod q with 12 bits per coefficient."""
        container = _require_mapping(container, label[0].upper() + label[1:])
        _, stored = codec.decode_packed(_field(container, "s", label), "s", (RANK, DEGREE), MODULUS)
        vector = module.centered(stored, MODULUS)
        if int(np.abs(vector).max()) > ETA:
            raise InvalidProtocolDataError(
                f"'s' en {label} contiene coeficientes fuera de la distribución CBD(eta)."
            )
        return vector

    @staticmethod
    def _share(container: SerializedData, label: str) -> np.ndarray:
        container = _require_mapping(container, label[0].upper() + label[1:])
        _, share = codec.decode_packed(_field(container, "b", label), "b", (RANK, DEGREE), MODULUS)
        return share

    @staticmethod
    def _parse_challenge(challenge: SerializedData) -> tuple[bytes, int]:
        challenge = _require_mapping(challenge, "El desafío")
        ticket = codec.decode_fixed_bytes(
            _field(challenge, "ticket", "el desafío"),
            "ticket",
            TICKET_BYTES,
        )
        nu = _require_int(_field(challenge, "nu", "el desafío"), "nu", 0, _MAX_TIMESTAMP)
        return ticket, nu

    @staticmethod
    def _challenge_seed(
        context: _Context,
        matrix_digest: bytes,
        public_key_digest: bytes,
        commitment_high_bits: np.ndarray,
        ticket: bytes,
        nu: int,
    ) -> bytes:
        """c~ = H(A', t, w1, ticket, nu): tex:76-79 with w replaced by its high bits.

        A' and t enter through their digests, which keeps H(t) as the only
        public-key material the prover has to store.
        """
        high_values = decomposition.high_values(context.rounding_step, PROOF_MODULUS)
        return _digest(
            _DOMAIN,
            b"challenge",
            context.parameters_digest,
            matrix_digest,
            public_key_digest,
            codec.pack_coefficients(commitment_high_bits, high_values),
            ticket,
            nu.to_bytes(TIMESTAMP_BYTES, "big"),
        )

    @staticmethod
    def _challenge_polynomial(context: _Context, seed: bytes) -> np.ndarray:
        """c = SampleInBall(c~): kappa coefficients in {-1, 1}, the rest zero."""
        return sampling.derive_sparse_ternary(seed, DEGREE, context.parameters["kappa"])

    def _now_ms(self) -> int:
        return int(self._clock() * 1000)

    # -- proof and token -------------------------------------------------------------

    def _prove(
        self,
        context: _Context,
        matrix: np.ndarray,
        matrix_digest: bytes,
        secret: np.ndarray,
        error: np.ndarray,
        public_key_digest: bytes,
        ticket: bytes,
        nu: int,
    ) -> tuple[np.ndarray, bytes, int]:
        """Return (z, c~, attempts); z has exact integer coefficients."""
        gamma1 = context.parameters["gamma1"]
        gamma2 = context.parameters["gamma2"]
        beta = context.parameters["beta"]
        alpha = context.rounding_step
        for attempt in range(1, MAX_PROOF_ATTEMPTS + 1):
            mask = sampling.sample_uniform_box(context.proof_shape, gamma1 - 1)   # y
            commitment = module.matrix_vector(matrix, mask, PROOF_MODULUS)        # w = A' y
            seed = self._challenge_seed(                                          # c~
                context,
                matrix_digest,
                public_key_digest,
                decomposition.high_bits(commitment, alpha, PROOF_MODULUS),        # w1
                ticket,
                nu,
            )
            challenge = self._challenge_polynomial(context, seed)                 # c
            response = mask + module.centered(                                    # z = y + c s
                module.scale_vector(challenge, secret, PROOF_MODULUS), PROOF_MODULUS
            )
            if int(np.abs(response).max()) >= gamma1 - beta:
                continue
            # A' z - c t, the value the verifier will rebuild, is w - c e.
            rebuilt = commitment - module.scale_vector(challenge, error, PROOF_MODULUS)
            low = decomposition.low_bits(rebuilt, alpha, PROOF_MODULUS)
            if int(np.abs(low).max()) >= gamma2 - beta:
                continue
            return response, seed, attempt
        raise CryptoCoreError(
            f"La prueba no terminó tras {MAX_PROOF_ATTEMPTS} intentos de rejection sampling."
        )

    @staticmethod
    def _token_associated_data(context: _Context) -> bytes:
        return _digest(_DOMAIN, b"token", context.parameters_digest)

    def _seal_token(
        self,
        context: _Context,
        response: np.ndarray,
        challenge_seed: bytes,
        ticket: bytes,
        nu: int,
    ) -> SerializedData:
        """tok = (tok1, tok2) hiding {z, c~, ticket, nu} (tex:98-120, with c~ in place of w)."""
        gamma1 = context.parameters["gamma1"]
        payload = (
            codec.pack_coefficients(np.asarray(response) + gamma1, 2 * gamma1)
            + challenge_seed
            + ticket
            + nu.to_bytes(TIMESTAMP_BYTES, "big")
        )
        tok1, tok2 = token_hiding.seal(
            context.verifier_public_key,
            payload,
            self._token_associated_data(context),
        )
        return {"tok1": codec.encode_bytes(tok1), "tok2": codec.encode_bytes(tok2)}

    def _open_token(
        self,
        context: _Context,
        state: _VerifierState,
        response: SerializedData,
    ) -> _OpenedToken | None:
        """Decrypt a token (tex:138-150); None when it was not sealed for this verifier."""
        response = _require_mapping(response, "La respuesta")
        tok1 = codec.decode_fixed_bytes(
            _field(response, "tok1", "la respuesta"),
            "tok1",
            token_hiding.CIPHERTEXT_BYTES,
        )
        tok2 = codec.decode_fixed_bytes(
            _field(response, "tok2", "la respuesta"),
            "tok2",
            token_hiding.sealed_length(context.payload_bytes),
        )
        payload = token_hiding.open_token(
            state.private_key(),
            tok1,
            tok2,
            self._token_associated_data(context),
        )
        if payload is None:
            return None
        gamma1 = context.parameters["gamma1"]
        seed_start = context.response_bytes
        ticket_start = seed_start + DIGEST_BYTES
        try:
            offsets = codec.unpack_coefficients(
                payload[:seed_start], "z", context.proof_shape, 2 * gamma1
            )
        except InvalidProtocolDataError:
            # Authentic ciphertext whose plaintext is not a response: a dishonest prover.
            return None
        return _OpenedToken(
            response=offsets - gamma1,
            challenge_seed=payload[seed_start:ticket_start],
            ticket=payload[ticket_start: ticket_start + TICKET_BYTES],
            nu=int.from_bytes(payload[-TIMESTAMP_BYTES:], "big"),
        )

    @staticmethod
    def _consume_ticket(
        state: _VerifierState,
        ticket: bytes,
        nu: int,
        horizon: int,
    ) -> bool:
        """Atomically test and extend the spent log (tex:159-163)."""
        with state.lock:
            if ticket in state.spent:
                return False
            if len(state.spent) >= _SPENT_LOG_PRUNE_SIZE:
                # Tickets older than the time window are rejected before this point,
                # so forgetting them cannot enable a replay.
                for log in (state.spent, state.authenticated):
                    for stale in [key for key, stamp in log.items() if stamp < horizon]:
                        del log[stale]
            state.spent[ticket] = nu
            return True

    # -- AuthProtocol --------------------------------------------------------------

    def generate_system_parameters(self, **params: Any) -> SerializedData:
        parameters = self.resolve_parameters(params)
        verifier_public_key, private_seed = token_hiding.generate_verifier_keypair()
        _KEYSTORE.register(_digest(_DOMAIN, b"verifier-key", verifier_public_key), private_seed)
        return {
            "protocol": PROTOCOL_ID,
            "parameters": parameters,
            "rho": codec.encode_bytes(secrets.token_bytes(SEED_BYTES)),
            "vpk": codec.encode_bytes(verifier_public_key),
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
        matrix, _ = self._proof_matrix(context)
        secret = sampling.sample_centered_binomial(context.proof_shape, ETA)
        error = sampling.sample_centered_binomial(context.proof_shape, ETA)
        public_vector = (                                                  # t = A' s + e
            module.matrix_vector(matrix, secret, PROOF_MODULUS) + error
        ) % PROOF_MODULUS
        public_raw = codec.pack_coefficients(public_vector, PROOF_MODULUS)
        return (
            {"t": codec.encode_bytes(public_raw)},
            {
                "s": codec.encode_packed(secret + ETA, _SECRET_RANGE),
                "e": codec.encode_packed(error + ETA, _SECRET_RANGE),
                "public_key_digest": codec.encode_bytes(
                    _digest(_DOMAIN, b"public-key", public_raw)
                ),
            },
        )

    def generate_challenge(
        self,
        system_parameters: SerializedData,
        public_key: SerializedData,
    ) -> SerializedData:
        self._context(system_parameters)
        # The proof binds t through H(A', t, w1, ticket, nu); the ticket itself is
        # not tied to an identity.
        del public_key
        return {
            "ticket": codec.encode_bytes(secrets.token_bytes(TICKET_BYTES)),
            "nu": self._now_ms(),
        }

    def solve_challenge(
        self,
        system_parameters: SerializedData,
        private_key: SerializedData,
        challenge: SerializedData,
    ) -> SerializedData:
        context = self._context(system_parameters)
        secret, error, public_key_digest = self._witness(context, private_key)
        ticket, nu = self._parse_challenge(challenge)
        matrix, matrix_digest = self._proof_matrix(context)
        response, challenge_seed, _ = self._prove(
            context,
            matrix,
            matrix_digest,
            secret,
            error,
            public_key_digest,
            ticket,
            nu,
        )
        return self._seal_token(context, response, challenge_seed, ticket, nu)

    def verify_response(
        self,
        system_parameters: SerializedData,
        public_key: SerializedData,
        challenge: SerializedData,
        response: SerializedData,
    ) -> bool:
        context = self._context(system_parameters)
        state = _KEYSTORE.get(context.verifier_key_id)
        public_key_digest, public_vector = self._public_vector(context, public_key)
        ticket, nu = self._parse_challenge(challenge)

        token = self._open_token(context, state, response)                        # tex:138-150
        if token is None:
            return False
        # Contract binding: the token must answer the challenge this verifier issued.
        if not hmac.compare_digest(token.ticket, ticket) or token.nu != nu:
            return False

        now = self._now_ms()
        window = 1000 * context.parameters["time_window_seconds"]
        if abs(now - token.nu) > window:                                          # tex:157
            return False
        if not self._consume_ticket(state, token.ticket, token.nu, now - window):  # tex:159-163
            return False

        if int(np.abs(token.response).max()) >= context.response_bound:           # tex:176-180
            return False
        matrix, matrix_digest = self._proof_matrix(context)
        challenge_polynomial = self._challenge_polynomial(context, token.challenge_seed)
        rebuilt = (                                                               # A' z - c t
            module.matrix_vector(matrix, token.response, PROOF_MODULUS)
            - module.scale_vector(challenge_polynomial, public_vector, PROOF_MODULUS)
        )
        expected_seed = self._challenge_seed(                                     # tex:171-174
            context,
            matrix_digest,
            public_key_digest,
            decomposition.high_bits(rebuilt, context.rounding_step, PROOF_MODULUS),
            token.ticket,
            token.nu,
        )
        if not hmac.compare_digest(expected_seed, token.challenge_seed):
            return False

        with state.lock:
            state.authenticated[token.ticket] = token.nu
        return True

    # -- session key agreement (manuscript Phase 4, outside the contract) ----------

    def generate_key_agreement_share(
        self,
        system_parameters: SerializedData,
        role: str,
    ) -> tuple[SerializedData, SerializedData]:
        """Return (public share {"b"}, secret {"s"}) for ``role`` "client" or "server".

        The client share is b_C = A s_C + e_C and the server share
        b_S = A^T s_S + e_S', with CBD(eta) secrets and errors over q = 3329, as
        in the source the manuscript cites; the manuscript itself does not
        define them.
        """
        if role not in ("client", "server"):
            raise InvalidProtocolDataError("'role' debe ser 'client' o 'server'.")
        context = self._context(system_parameters)
        matrix = self._agreement_matrix(context)
        if role == "server":
            matrix = module.transpose(matrix)
        secret = sampling.sample_centered_binomial((RANK, DEGREE), ETA)
        error = sampling.sample_centered_binomial((RANK, DEGREE), ETA)
        share = (module.matrix_vector(matrix, secret, MODULUS) + error) % MODULUS
        return (
            {"b": codec.encode_packed(share, MODULUS)},
            {"s": codec.encode_packed(secret % MODULUS, MODULUS)},
        )

    def generate_reconciliation_hint(
        self,
        system_parameters: SerializedData,
        challenge: SerializedData,
        client_share: SerializedData,
        server_secret: SerializedData,
    ) -> tuple[SerializedData, bytes]:
        """Server side: return (hint {"v"}, K_S) for an authenticated session.

        Only a ticket accepted by ``verify_response`` can obtain a hint, and
        only once (tex:198, tex:250-259). The hint is public; K_S is not.
        """
        context = self._context(system_parameters)
        state = _KEYSTORE.get(context.verifier_key_id)
        ticket, _ = self._parse_challenge(challenge)
        share = self._share(client_share, "la cuota del cliente")
        secret = self._small_vector(server_secret, "el secreto del servidor")
        with state.lock:
            if state.authenticated.pop(ticket, None) is None:
                raise InvalidProtocolDataError(
                    "El ticket no corresponde a una sesión autenticada pendiente de pista."
                )
        error = sampling.sample_centered_binomial((DEGREE,), ETA)
        base = (module.inner_product(share, secret, MODULUS) + error) % MODULUS    # w_B  tex:250-253
        session_key = reconciliation.modular_round(base, MODULUS)                 # K_S  tex:255-258
        hint = reconciliation.cross_round(base, MODULUS)                          # v
        return (
            {"v": codec.encode_bytes(reconciliation.bits_to_bytes(hint))},
            reconciliation.bits_to_bytes(session_key),
        )

    def reconcile_session_key(
        self,
        system_parameters: SerializedData,
        server_share: SerializedData,
        client_secret: SerializedData,
        hint: SerializedData,
    ) -> bytes:
        """Client side: return K_C = rec(b_S^T s_C, v) (tex:263-266)."""
        self._context(system_parameters)
        share = self._share(server_share, "la cuota del servidor")
        secret = self._small_vector(client_secret, "el secreto del cliente")
        hint = _require_mapping(hint, "La pista")
        hint_bits = reconciliation.bytes_to_bits(
            codec.decode_fixed_bytes(_field(hint, "v", "la pista"), "v", HINT_BYTES),
            DEGREE,
        )
        base = module.inner_product(share, secret, MODULUS)                       # w_A
        return reconciliation.bits_to_bytes(
            reconciliation.reconcile(base, hint_bits, MODULUS)
        )
