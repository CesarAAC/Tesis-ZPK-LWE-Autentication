"""Challenge/response authentication from Regev LWE encryption.

Implements the ``standard_lwe`` and ``binary_lwe`` candidates. Both share the
same protocol template and differ only in the distribution of the secret
``s``, so any measured difference between them is attributable to that choice.

Setup (per deployment)
    A <- U(Z_q^{m x n}), published in ``system_parameters`` with the effective
    parameters.

Enrollment (per user)
    s <- U(Z_q^n) (standard) or U({0,1}^n) (binary), e <- D_sigma^m,
    b = A s + e mod q. Public key: b. Private key: s and b (b is kept so the
    prover can re-encrypt; as in Kyber/Frodo, the secret key embeds the public key).

Authentication (per session)
    1. Verifier: fresh nonce and message mu <- {0,1}^k. Encryption randomness
       R in {0,1}^{k x m} is derived as SHAKE-256(H(nonce, H(pk), mu)), every
       bit of mu is Regev-encrypted under b, and the challenge carries
       (nonce, U, V, commitment = H(params, H(pk), nonce, U, V, mu)).
    2. Prover: decrypts mu', re-derives R' from mu' and re-encrypts. It answers
       mu' only when (U', V') == (U, V) and the commitment matches
       (Fujisaki-Okamoto style check). A malformed challenge is refused, so a
       malicious verifier cannot use the prover as a decryption oracle to
       recover s.
    3. Verifier: accepts iff H(params, H(pk), nonce, U, V, mu') equals the
       commitment of the challenge it issued.

The challenge is verifier session state: in a deployment the server keeps the
challenge it issued and verifies against that copy. The commitment lets the
server store the challenge without storing mu in clear. A verifier that
accepted a challenge supplied by the client would be trivially bypassed.

Security notes
    * m >= (n + 1) * ceil(log2 q) + 256 is enforced (leftover hash lemma).
      Smaller m turns r^T A into a low-density subset-sum instance that lattice
      reduction solves, which would reveal mu without the secret key.
    * Default (n, q, sigma) = (640, 2^15, 2.8) follows FrodoKEM-640. They are a
      starting point, not a security proof: the effective security of each
      parameter set (in particular with a binary secret, which is weaker for
      the same n) must be estimated separately and recorded as evidence.
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

from crypto_core.exceptions import InvalidProtocolDataError
from crypto_core.interface import AuthProtocol, KeyPair, SerializedData
from crypto_core.lwe import codec, regev, sampling

_DOMAIN = b"lwe-auth/regev-fo-challenge-response/v1"

_DEFAULT_N = 640
_DEFAULT_Q = 1 << 15
_DEFAULT_SIGMA = 2.8
_DEFAULT_MESSAGE_BITS = 128

_MAX_N = 4096
_MAX_MATRIX_COEFFICIENTS = 1 << 26
_MIN_MESSAGE_BITS = 128
_MAX_MESSAGE_BITS = 512
# floor(q / 4) must exceed this many standard deviations of <r, e>, which is
# at most sigma * sqrt(m); a decryption failure would reject a legitimate user.
_DECRYPTION_MARGIN_SIGMAS = 10
_NONCE_BYTES = 32
_DIGEST_BYTES = 32


def _fixed_parameters(secret_distribution: str) -> SerializedData:
    return {
        "secret_distribution": secret_distribution,
        "error_distribution": "discrete_gaussian_cdt",
        "error_tail_sigmas": 12,
        "matrix_distribution": "uniform_mod_q_shared",
        "encryption_randomness": "binary_shake256_derived",
        "transform": "fujisaki_okamoto_reencryption",
        "nonce_bytes": _NONCE_BYTES,
        "hash": "sha3-256",
        "xof": "shake256",
        "leftover_hash_slack_bits": 256,
        "coefficient_encoding": "uint16le_base64",
    }


def _require_int(value: Any, name: str, minimum: int, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidProtocolDataError(f"'{name}' debe ser un entero.")
    if value < minimum:
        raise InvalidProtocolDataError(f"'{name}' debe ser al menos {minimum}.")
    if maximum is not None and value > maximum:
        raise InvalidProtocolDataError(f"'{name}' no puede superar {maximum}.")
    return value


def _require_sigma(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidProtocolDataError("'sigma' debe ser numérico.")
    sigma = float(value)
    if not math.isfinite(sigma) or sigma <= 0:
        raise InvalidProtocolDataError("'sigma' debe ser positivo y finito.")
    return sigma


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


@dataclass(frozen=True, slots=True)
class _Context:
    parameters: SerializedData
    parameters_digest: bytes
    n: int
    m: int
    q: int
    message_bits: int


@dataclass(frozen=True, slots=True)
class _Challenge:
    nonce: bytes
    u_raw: bytes
    u: np.ndarray
    v_raw: bytes
    v: np.ndarray
    commitment: bytes


class _RegevLWEAuthProtocol(AuthProtocol):
    """Shared template; subclasses only choose the secret distribution."""

    protocol_id = ""
    secret_distribution = ""

    @property
    def name(self) -> str:
        return self.protocol_id

    # -- secret distribution hooks -------------------------------------------------

    def _sample_secret(self, context: _Context) -> np.ndarray:
        raise NotImplementedError

    def _encode_secret(self, secret: np.ndarray) -> str:
        raise NotImplementedError

    def _decode_secret(self, value: Any, context: _Context) -> np.ndarray:
        raise NotImplementedError

    # -- parameters ----------------------------------------------------------------

    def default_parameters(self) -> SerializedData:
        fixed = _fixed_parameters(self.secret_distribution)
        return {
            "n": _DEFAULT_N,
            "m": regev.leftover_hash_min_samples(
                _DEFAULT_N,
                _DEFAULT_Q,
                fixed["leftover_hash_slack_bits"],
            ),
            "q": _DEFAULT_Q,
            "sigma": _DEFAULT_SIGMA,
            "message_bits": _DEFAULT_MESSAGE_BITS,
            **fixed,
        }

    def resolve_parameters(
        self, overrides: SerializedData | None = None
    ) -> SerializedData:
        overrides = _require_mapping(
            {} if overrides is None else overrides,
            "Los parámetros",
        )
        defaults = self.default_parameters()
        unknown = set(overrides) - set(defaults)
        if unknown:
            raise InvalidProtocolDataError(
                f"Parámetros {self.protocol_id} desconocidos: {sorted(unknown)}."
            )

        fixed = _fixed_parameters(self.secret_distribution)
        for key, expected in fixed.items():
            if key in overrides and overrides[key] != expected:
                raise InvalidProtocolDataError(
                    f"'{key}' está fijado a {expected!r} en {self.protocol_id}."
                )

        n = _require_int(overrides.get("n", defaults["n"]), "n", 1, _MAX_N)
        q = _require_int(
            overrides.get("q", defaults["q"]),
            "q",
            2,
            codec.MAX_ENCODABLE_MODULUS,
        )
        sigma = _require_sigma(overrides.get("sigma", defaults["sigma"]))
        message_bits = _require_int(
            overrides.get("message_bits", defaults["message_bits"]),
            "message_bits",
            _MIN_MESSAGE_BITS,
            _MAX_MESSAGE_BITS,
        )
        if message_bits % 8:
            raise InvalidProtocolDataError("'message_bits' debe ser múltiplo de 8.")

        minimum_m = regev.leftover_hash_min_samples(
            n,
            q,
            fixed["leftover_hash_slack_bits"],
        )
        m = (
            _require_int(overrides["m"], "m", 1)
            if "m" in overrides
            else minimum_m
        )
        if m < minimum_m:
            raise InvalidProtocolDataError(
                f"'m' debe ser al menos (n + 1) * ceil(log2 q) + "
                f"{fixed['leftover_hash_slack_bits']} = {minimum_m}; con menos "
                "muestras el desafío puede resolverse sin la clave privada."
            )
        if m * n > _MAX_MATRIX_COEFFICIENTS:
            raise InvalidProtocolDataError(
                f"La matriz A excede {_MAX_MATRIX_COEFFICIENTS} coeficientes."
            )
        if m * (q - 1) >= regev.FLOAT64_EXACT_LIMIT:
            raise InvalidProtocolDataError(
                "m * (q - 1) debe ser menor que 2^53 para mantener aritmética exacta."
            )
        if q // 4 <= _DECRYPTION_MARGIN_SIGMAS * sigma * math.sqrt(m):
            raise InvalidProtocolDataError(
                "q es demasiado pequeño para sigma y m: la desencriptación fallaría "
                "con probabilidad no despreciable."
            )

        return {
            "n": n,
            "m": m,
            "q": q,
            "sigma": sigma,
            "message_bits": message_bits,
            **fixed,
        }

    def _context(self, system_parameters: SerializedData) -> _Context:
        system_parameters = _require_mapping(
            system_parameters,
            "Los parámetros del sistema",
        )
        protocol = _field(system_parameters, "protocol", "los parámetros del sistema")
        if protocol != self.protocol_id:
            raise InvalidProtocolDataError(
                f"Los parámetros del sistema pertenecen a '{protocol}', "
                f"no a '{self.protocol_id}'."
            )
        parameters = _require_mapping(
            _field(system_parameters, "parameters", "los parámetros del sistema"),
            "'parameters'",
        )
        if self.resolve_parameters(parameters) != parameters:
            raise InvalidProtocolDataError(
                "Los parámetros del sistema no son el conjunto efectivo completo."
            )
        canonical = json.dumps(
            parameters,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return _Context(
            parameters=parameters,
            parameters_digest=_digest(_DOMAIN, b"parameters", canonical),
            n=parameters["n"],
            m=parameters["m"],
            q=parameters["q"],
            message_bits=parameters["message_bits"],
        )

    @staticmethod
    def _matrix_a(system_parameters: SerializedData, context: _Context) -> np.ndarray:
        return codec.decode_coefficients(
            _field(system_parameters, "matrix_a", "los parámetros del sistema"),
            "matrix_a",
            (context.m, context.n),
            context.q,
        )

    @staticmethod
    def _public_vector(
        container: SerializedData,
        label: str,
        context: _Context,
    ) -> tuple[bytes, np.ndarray]:
        container = _require_mapping(container, label)
        raw, vector_b = codec.decode_coefficient_bytes(
            _field(container, "b", label),
            "b",
            (context.m,),
            context.q,
        )
        return raw, vector_b.astype(np.int64)

    def _public_key_digest(self, context: _Context, b_raw: bytes) -> bytes:
        return _digest(
            _DOMAIN,
            b"public-key",
            self.protocol_id.encode("ascii"),
            context.parameters_digest,
            b_raw,
        )

    # -- challenge construction ----------------------------------------------------

    def _encrypt_message(
        self,
        context: _Context,
        matrix_a_float: np.ndarray,
        vector_b: np.ndarray,
        public_key_digest: bytes,
        nonce: bytes,
        message: bytes,
    ) -> tuple[np.ndarray, np.ndarray]:
        bits = np.unpackbits(
            np.frombuffer(message, dtype=np.uint8),
            bitorder="little",
        ).astype(np.int64)
        seed = _digest(_DOMAIN, b"encryption-randomness", public_key_digest, nonce, message)
        randomness = sampling.derive_binary_matrix(seed, (context.message_bits, context.m))
        return regev.encrypt_bits(matrix_a_float, vector_b, bits, randomness, context.q)

    def _commitment(
        self,
        context: _Context,
        public_key_digest: bytes,
        nonce: bytes,
        u_raw: bytes,
        v_raw: bytes,
        message: bytes,
    ) -> bytes:
        return _digest(
            _DOMAIN,
            b"commitment",
            self.protocol_id.encode("ascii"),
            context.parameters_digest,
            public_key_digest,
            nonce,
            u_raw,
            v_raw,
            message,
        )

    def _parse_challenge(self, challenge: SerializedData, context: _Context) -> _Challenge:
        challenge = _require_mapping(challenge, "El desafío")
        nonce = codec.decode_fixed_bytes(
            _field(challenge, "nonce", "el desafío"),
            "nonce",
            _NONCE_BYTES,
        )
        u_raw, u = codec.decode_coefficient_bytes(
            _field(challenge, "u", "el desafío"),
            "u",
            (context.message_bits, context.n),
            context.q,
        )
        v_raw, v = codec.decode_coefficient_bytes(
            _field(challenge, "v", "el desafío"),
            "v",
            (context.message_bits,),
            context.q,
        )
        commitment = codec.decode_fixed_bytes(
            _field(challenge, "commitment", "el desafío"),
            "commitment",
            _DIGEST_BYTES,
        )
        return _Challenge(
            nonce=nonce,
            u_raw=u_raw,
            u=u.astype(np.int64),
            v_raw=v_raw,
            v=v.astype(np.int64),
            commitment=commitment,
        )

    # -- AuthProtocol --------------------------------------------------------------

    def generate_system_parameters(self, **params: Any) -> SerializedData:
        parameters = self.resolve_parameters(params)
        matrix_a = sampling.sample_uniform_mod_q(
            (parameters["m"], parameters["n"]),
            parameters["q"],
        )
        return {
            "protocol": self.protocol_id,
            "parameters": parameters,
            "matrix_a": codec.encode_coefficients(matrix_a),
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
        matrix_a = self._matrix_a(system_parameters, context)
        secret = self._sample_secret(context)
        error = sampling.sample_discrete_gaussian(
            (context.m,),
            context.parameters["sigma"],
            context.parameters["error_tail_sigmas"],
        )
        vector_b = regev.public_vector(matrix_a, secret, error, context.q)
        encoded_b = codec.encode_coefficients(vector_b)
        return (
            {"b": encoded_b},
            {"s": self._encode_secret(secret), "b": encoded_b},
        )

    def generate_challenge(
        self,
        system_parameters: SerializedData,
        public_key: SerializedData,
    ) -> SerializedData:
        context = self._context(system_parameters)
        b_raw, vector_b = self._public_vector(public_key, "la clave pública", context)
        public_key_digest = self._public_key_digest(context, b_raw)
        matrix_a_float = self._matrix_a(system_parameters, context).astype(np.float64)

        nonce = secrets.token_bytes(_NONCE_BYTES)
        message = secrets.token_bytes(context.message_bits // 8)
        u, v = self._encrypt_message(
            context,
            matrix_a_float,
            vector_b,
            public_key_digest,
            nonce,
            message,
        )
        u_raw = codec.coefficient_bytes(u)
        v_raw = codec.coefficient_bytes(v)
        commitment = self._commitment(context, public_key_digest, nonce, u_raw, v_raw, message)
        return {
            "nonce": codec.encode_bytes(nonce),
            "u": codec.encode_bytes(u_raw),
            "v": codec.encode_bytes(v_raw),
            "commitment": codec.encode_bytes(commitment),
        }

    def solve_challenge(
        self,
        system_parameters: SerializedData,
        private_key: SerializedData,
        challenge: SerializedData,
    ) -> SerializedData:
        context = self._context(system_parameters)
        private_key = _require_mapping(private_key, "La clave privada")
        secret = self._decode_secret(_field(private_key, "s", "la clave privada"), context)
        b_raw, vector_b = self._public_vector(private_key, "la clave privada", context)
        parsed = self._parse_challenge(challenge, context)

        bits = regev.decrypt_bits(parsed.u, parsed.v, secret, context.q)
        message = np.packbits(bits.astype(np.uint8), bitorder="little").tobytes()

        public_key_digest = self._public_key_digest(context, b_raw)
        matrix_a_float = self._matrix_a(system_parameters, context).astype(np.float64)
        expected_u, expected_v = self._encrypt_message(
            context,
            matrix_a_float,
            vector_b,
            public_key_digest,
            parsed.nonce,
            message,
        )
        expected_commitment = self._commitment(
            context,
            public_key_digest,
            parsed.nonce,
            parsed.u_raw,
            parsed.v_raw,
            message,
        )
        if not (
            np.array_equal(expected_u, parsed.u)
            and np.array_equal(expected_v, parsed.v)
            and hmac.compare_digest(expected_commitment, parsed.commitment)
        ):
            raise InvalidProtocolDataError(
                "El desafío no es una encriptación válida para esta clave; "
                "se rechaza sin revelar la desencriptación."
            )
        return {"message": codec.encode_bytes(message)}

    def verify_response(
        self,
        system_parameters: SerializedData,
        public_key: SerializedData,
        challenge: SerializedData,
        response: SerializedData,
    ) -> bool:
        context = self._context(system_parameters)
        b_raw, _ = self._public_vector(public_key, "la clave pública", context)
        parsed = self._parse_challenge(challenge, context)
        response = _require_mapping(response, "La respuesta")
        message = codec.decode_fixed_bytes(
            _field(response, "message", "la respuesta"),
            "message",
            context.message_bits // 8,
        )
        expected_commitment = self._commitment(
            context,
            self._public_key_digest(context, b_raw),
            parsed.nonce,
            parsed.u_raw,
            parsed.v_raw,
            message,
        )
        return hmac.compare_digest(expected_commitment, parsed.commitment)


class StandardLWEProtocol(_RegevLWEAuthProtocol):
    """Regev LWE authentication with a secret uniform in Z_q^n."""

    protocol_id = "standard_lwe"
    secret_distribution = "uniform_mod_q"

    def _sample_secret(self, context: _Context) -> np.ndarray:
        return sampling.sample_uniform_mod_q((context.n,), context.q)

    def _encode_secret(self, secret: np.ndarray) -> str:
        return codec.encode_coefficients(secret)

    def _decode_secret(self, value: Any, context: _Context) -> np.ndarray:
        return codec.decode_coefficients(value, "s", (context.n,), context.q)


class BinaryLWEProtocol(_RegevLWEAuthProtocol):
    """Regev LWE authentication with a secret uniform in {0, 1}^n."""

    protocol_id = "binary_lwe"
    secret_distribution = "binary"

    def _sample_secret(self, context: _Context) -> np.ndarray:
        return sampling.sample_binary((context.n,))

    def _encode_secret(self, secret: np.ndarray) -> str:
        return codec.encode_bits(secret)

    def _decode_secret(self, value: Any, context: _Context) -> np.ndarray:
        return codec.decode_bits(value, "s", context.n)
