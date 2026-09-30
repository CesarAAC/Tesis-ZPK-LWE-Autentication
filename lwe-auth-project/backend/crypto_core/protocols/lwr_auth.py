"""Learning With Rounding challenge/response authentication prototype.

This candidate mirrors the observable lifecycle of the Regev-LWE candidates
while replacing sampled additive error with deterministic modulus rounding.
A deployment publishes A in Z_q^{m x n}; enrollment samples s uniformly in
Z_q^n and publishes b = Round_p(A s).  Authentication encrypts a fresh random
message using binary subset-sum randomness derived from SHAKE-256, and the
prover performs a Fujisaki-Okamoto-style re-encryption check before returning
the recovered message.

The defaults are research parameters only.  They are not a claim of 128-bit
security and must be assessed independently before thesis conclusions use them.
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
from crypto_core.lwe import codec, lwr, regev, sampling

_DOMAIN = b"lwe-auth/lwr-fo-challenge-response/v1"
_DEFAULT_N = 640
_DEFAULT_Q = 1 << 15
_DEFAULT_P = 1 << 12
_DEFAULT_MESSAGE_BITS = 128
_MIN_N = 1
_MAX_N = 4096
_MAX_MATRIX_COEFFICIENTS = 1 << 26
_MIN_MESSAGE_BITS = 128
_MAX_MESSAGE_BITS = 512
_NONCE_BYTES = 32
_DIGEST_BYTES = 32
_ROUNDING_MARGIN_SIGMAS = 10


def _fixed_parameters() -> SerializedData:
    return {
        "secret_distribution": "uniform_mod_q",
        "noise_mechanism": "deterministic_modulus_rounding",
        "matrix_distribution": "uniform_mod_q_shared",
        "encryption_randomness": "binary_shake256_derived",
        "transform": "fujisaki_okamoto_reencryption",
        "nonce_bytes": _NONCE_BYTES,
        "hash": "sha3-256",
        "xof": "shake256",
        "leftover_hash_slack_bits": 256,
        "coefficient_encoding": "uint16le_base64",
    }


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InvalidProtocolDataError(f"{label} debe ser un objeto JSON.")
    return value


def _field(container: dict[str, Any], key: str, label: str) -> Any:
    try:
        return container[key]
    except KeyError as exc:
        raise InvalidProtocolDataError(f"Falta '{key}' en {label}.") from exc


def _require_int(value: Any, name: str, minimum: int, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidProtocolDataError(f"'{name}' debe ser un entero.")
    if value < minimum:
        raise InvalidProtocolDataError(f"'{name}' debe ser al menos {minimum}.")
    if maximum is not None and value > maximum:
        raise InvalidProtocolDataError(f"'{name}' no puede superar {maximum}.")
    return value


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _digest(*parts: bytes) -> bytes:
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
    p: int
    message_bits: int


@dataclass(frozen=True, slots=True)
class _Challenge:
    nonce: bytes
    u_raw: bytes
    u: np.ndarray
    v_raw: bytes
    v: np.ndarray
    commitment: bytes


class LWRProtocol(AuthProtocol):
    protocol_id = "lwr"

    @property
    def name(self) -> str:
        return self.protocol_id

    def default_parameters(self) -> SerializedData:
        fixed = _fixed_parameters()
        return {
            "n": _DEFAULT_N,
            "m": regev.leftover_hash_min_samples(
                _DEFAULT_N, _DEFAULT_Q, fixed["leftover_hash_slack_bits"]
            ),
            "q": _DEFAULT_Q,
            "p": _DEFAULT_P,
            "message_bits": _DEFAULT_MESSAGE_BITS,
            **fixed,
        }

    def resolve_parameters(self, overrides: SerializedData | None = None) -> SerializedData:
        overrides = _require_mapping({} if overrides is None else overrides, "Los parámetros")
        defaults = self.default_parameters()
        unknown = set(overrides) - set(defaults)
        if unknown:
            raise InvalidProtocolDataError(f"Parámetros lwr desconocidos: {sorted(unknown)}.")

        fixed = _fixed_parameters()
        for key, expected in fixed.items():
            if key in overrides and overrides[key] != expected:
                raise InvalidProtocolDataError(f"'{key}' está fijado a {expected!r} en lwr.")

        n = _require_int(overrides.get("n", defaults["n"]), "n", _MIN_N, _MAX_N)
        q = _require_int(overrides.get("q", defaults["q"]), "q", 4, codec.MAX_ENCODABLE_MODULUS)
        p = _require_int(overrides.get("p", defaults["p"]), "p", 4, codec.MAX_ENCODABLE_MODULUS)
        message_bits = _require_int(
            overrides.get("message_bits", defaults["message_bits"]),
            "message_bits", _MIN_MESSAGE_BITS, _MAX_MESSAGE_BITS,
        )
        if message_bits % 8:
            raise InvalidProtocolDataError("'message_bits' debe ser múltiplo de 8.")
        if not (_is_power_of_two(q) and _is_power_of_two(p)):
            raise InvalidProtocolDataError("'q' y 'p' deben ser potencias de dos en esta implementación LWR.")
        if p >= q or q % p:
            raise InvalidProtocolDataError("LWR requiere p < q y p divisor de q.")

        minimum_m = regev.leftover_hash_min_samples(n, q, fixed["leftover_hash_slack_bits"])
        m = _require_int(overrides["m"], "m", 1) if "m" in overrides else minimum_m
        if m < minimum_m:
            raise InvalidProtocolDataError(
                f"'m' debe ser al menos (n + 1) * ceil(log2 q) + "
                f"{fixed['leftover_hash_slack_bits']} = {minimum_m}."
            )
        if m * n > _MAX_MATRIX_COEFFICIENTS:
            raise InvalidProtocolDataError(f"La matriz A excede {_MAX_MATRIX_COEFFICIENTS} coeficientes.")
        if m * (q - 1) >= regev.FLOAT64_EXACT_LIMIT:
            raise InvalidProtocolDataError("m * (q - 1) debe ser menor que 2^53 para aritmética exacta.")
        if n * (q - 1) * (q - 1) >= regev.INT64_LIMIT:
            raise InvalidProtocolDataError("n * (q - 1)^2 excede el margen de int64.")

        # Each rounded public sample contributes an error bounded by 1/2 in Z_p.
        # This is a conservative engineering correctness check, not a security proof.
        rounding_std_upper = 0.5 * math.sqrt(m) + 0.5
        if p // 4 <= _ROUNDING_MARGIN_SIGMAS * rounding_std_upper:
            raise InvalidProtocolDataError(
                "p es demasiado pequeño para m: el margen de corrección del redondeo es insuficiente."
            )

        return {"n": n, "m": m, "q": q, "p": p,
                "message_bits": message_bits, **fixed}

    def _context(self, system_parameters: SerializedData) -> _Context:
        system_parameters = _require_mapping(system_parameters, "Los parámetros del sistema")
        protocol = _field(system_parameters, "protocol", "los parámetros del sistema")
        if protocol != self.protocol_id:
            raise InvalidProtocolDataError(
                f"Los parámetros del sistema pertenecen a '{protocol}', no a '{self.protocol_id}'."
            )
        parameters = _require_mapping(
            _field(system_parameters, "parameters", "los parámetros del sistema"), "'parameters'"
        )
        if self.resolve_parameters(parameters) != parameters:
            raise InvalidProtocolDataError("Los parámetros del sistema no son el conjunto efectivo completo.")
        canonical = json.dumps(parameters, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return _Context(parameters, _digest(_DOMAIN, b"parameters", canonical),
                        parameters["n"], parameters["m"], parameters["q"],
                        parameters["p"], parameters["message_bits"])

    @staticmethod
    def _matrix_a(system_parameters: SerializedData, context: _Context) -> np.ndarray:
        return codec.decode_coefficients(
            _field(system_parameters, "matrix_a", "los parámetros del sistema"),
            "matrix_a", (context.m, context.n), context.q,
        )

    @staticmethod
    def _public_vector(container: SerializedData, label: str, context: _Context) -> tuple[bytes, np.ndarray]:
        container = _require_mapping(container, label)
        raw, vector = codec.decode_coefficient_bytes(
            _field(container, "b", label), "b", (context.m,), context.p,
        )
        return raw, vector.astype(np.int64)

    def _public_key_digest(self, context: _Context, b_raw: bytes) -> bytes:
        return _digest(_DOMAIN, b"public-key", context.parameters_digest, b_raw)

    def _encrypt_message(self, context: _Context, matrix_a_float: np.ndarray,
                         vector_b: np.ndarray, public_key_digest: bytes,
                         nonce: bytes, message: bytes) -> tuple[np.ndarray, np.ndarray]:
        bits = np.unpackbits(np.frombuffer(message, dtype=np.uint8), bitorder="little").astype(np.int64)
        seed = _digest(_DOMAIN, b"encryption-randomness", public_key_digest, nonce, message)
        randomness = sampling.derive_binary_matrix(seed, (context.message_bits, context.m))
        return lwr.encrypt_bits(matrix_a_float, vector_b, bits, randomness, context.q, context.p)

    def _commitment(self, context: _Context, public_key_digest: bytes, nonce: bytes,
                    u_raw: bytes, v_raw: bytes, message: bytes) -> bytes:
        return _digest(_DOMAIN, b"commitment", context.parameters_digest,
                       public_key_digest, nonce, u_raw, v_raw, message)

    def _parse_challenge(self, challenge: SerializedData, context: _Context) -> _Challenge:
        challenge = _require_mapping(challenge, "El desafío")
        nonce = codec.decode_fixed_bytes(_field(challenge, "nonce", "el desafío"), "nonce", _NONCE_BYTES)
        u_raw, u = codec.decode_coefficient_bytes(
            _field(challenge, "u", "el desafío"), "u", (context.message_bits, context.n), context.q,
        )
        v_raw, v = codec.decode_coefficient_bytes(
            _field(challenge, "v", "el desafío"), "v", (context.message_bits,), context.p,
        )
        commitment = codec.decode_fixed_bytes(
            _field(challenge, "commitment", "el desafío"), "commitment", _DIGEST_BYTES,
        )
        return _Challenge(nonce, u_raw, u.astype(np.int64), v_raw, v.astype(np.int64), commitment)

    def generate_system_parameters(self, **params: Any) -> SerializedData:
        parameters = self.resolve_parameters(params)
        matrix_a = sampling.sample_uniform_mod_q((parameters["m"], parameters["n"]), parameters["q"])
        return {"protocol": self.protocol_id, "parameters": parameters,
                "matrix_a": codec.encode_coefficients(matrix_a)}

    def generate_keypair(self, system_parameters: SerializedData, **params: Any) -> KeyPair:
        context = self._context(system_parameters)
        if self.resolve_parameters(params) != context.parameters:
            raise InvalidProtocolDataError("Los parámetros de enrollment no coinciden con los del setup.")
        matrix_a = self._matrix_a(system_parameters, context)
        secret = sampling.sample_uniform_mod_q((context.n,), context.q)
        vector_b = lwr.public_vector(matrix_a, secret, context.q, context.p)
        encoded_b = codec.encode_coefficients(vector_b)
        return ({"b": encoded_b}, {"s": codec.encode_coefficients(secret), "b": encoded_b})

    def generate_challenge(self, system_parameters: SerializedData, public_key: SerializedData) -> SerializedData:
        context = self._context(system_parameters)
        b_raw, vector_b = self._public_vector(public_key, "la clave pública", context)
        pk_digest = self._public_key_digest(context, b_raw)
        matrix_a_float = self._matrix_a(system_parameters, context).astype(np.float64)
        nonce = secrets.token_bytes(_NONCE_BYTES)
        message = secrets.token_bytes(context.message_bits // 8)
        u, v = self._encrypt_message(context, matrix_a_float, vector_b, pk_digest, nonce, message)
        u_raw, v_raw = codec.coefficient_bytes(u), codec.coefficient_bytes(v)
        commitment = self._commitment(context, pk_digest, nonce, u_raw, v_raw, message)
        return {"nonce": codec.encode_bytes(nonce), "u": codec.encode_bytes(u_raw),
                "v": codec.encode_bytes(v_raw), "commitment": codec.encode_bytes(commitment)}

    def solve_challenge(self, system_parameters: SerializedData, private_key: SerializedData,
                        challenge: SerializedData) -> SerializedData:
        context = self._context(system_parameters)
        private_key = _require_mapping(private_key, "La clave privada")
        secret = codec.decode_coefficients(_field(private_key, "s", "la clave privada"),
                                           "s", (context.n,), context.q)
        b_raw, vector_b = self._public_vector(private_key, "la clave privada", context)
        parsed = self._parse_challenge(challenge, context)
        bits = lwr.decrypt_bits(parsed.u, parsed.v, secret, context.q, context.p)
        message = np.packbits(bits.astype(np.uint8), bitorder="little").tobytes()
        pk_digest = self._public_key_digest(context, b_raw)
        matrix_a_float = self._matrix_a(system_parameters, context).astype(np.float64)
        expected_u, expected_v = self._encrypt_message(
            context, matrix_a_float, vector_b, pk_digest, parsed.nonce, message
        )
        expected_commitment = self._commitment(
            context, pk_digest, parsed.nonce, parsed.u_raw, parsed.v_raw, message
        )
        if not (np.array_equal(expected_u, parsed.u) and np.array_equal(expected_v, parsed.v)
                and hmac.compare_digest(expected_commitment, parsed.commitment)):
            raise InvalidProtocolDataError(
                "El desafío no es una encriptación LWR válida para esta clave; se rechaza sin revelar la desencriptación."
            )
        return {"message": codec.encode_bytes(message)}

    def verify_response(self, system_parameters: SerializedData, public_key: SerializedData,
                        challenge: SerializedData, response: SerializedData) -> bool:
        context = self._context(system_parameters)
        b_raw, _ = self._public_vector(public_key, "la clave pública", context)
        parsed = self._parse_challenge(challenge, context)
        response = _require_mapping(response, "La respuesta")
        message = codec.decode_fixed_bytes(_field(response, "message", "la respuesta"),
                                           "message", context.message_bits // 8)
        expected = self._commitment(context, self._public_key_digest(context, b_raw),
                                    parsed.nonce, parsed.u_raw, parsed.v_raw, message)
        return hmac.compare_digest(expected, parsed.commitment)
