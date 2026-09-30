"""Ring-LWE challenge/response authentication prototype.

The protocol uses the ring R_q = Z_q[x]/(x^n + 1).  A deployment publishes a
uniform polynomial ``a``.  Enrollment samples small centered-binomial ``s,e``
and publishes ``b = a*s + e``.  Authentication encrypts a fresh random message
with deterministic SHAKE-derived Ring-LWE randomness and applies a
Fujisaki-Okamoto-style re-encryption check before the prover reveals the
plaintext response.

The default parameters are research defaults, not a security proof.  Effective
security must be estimated independently and stored as benchmark evidence.
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
from crypto_core.lwe import codec, ring, sampling

_DOMAIN = b"lwe-auth/ring-lwe-fo-challenge-response/v1"
_DEFAULT_N = 512
_DEFAULT_Q = 12289
_DEFAULT_ETA = 2
_DEFAULT_MESSAGE_BITS = 128
_MIN_N = 128
_MAX_N = 4096
_MIN_MESSAGE_BITS = 128
_MAX_MESSAGE_BITS = 512
_NONCE_BYTES = 32
_DIGEST_BYTES = 32
_CORRECTNESS_MARGIN_SIGMAS = 12


def _fixed_parameters() -> SerializedData:
    return {
        "ring": "Z_q[x]/(x^n+1)",
        "secret_distribution": "centered_binomial",
        "error_distribution": "centered_binomial",
        "ephemeral_distribution": "centered_binomial_shake256_derived",
        "transform": "fujisaki_okamoto_reencryption",
        "nonce_bytes": _NONCE_BYTES,
        "hash": "sha3-256",
        "xof": "shake256",
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
    if value < minimum or (maximum is not None and value > maximum):
        suffix = f" y no mayor que {maximum}" if maximum is not None else ""
        raise InvalidProtocolDataError(f"'{name}' debe ser al menos {minimum}{suffix}.")
    return value


def _digest(*parts: bytes) -> bytes:
    hasher = hashlib.sha3_256()
    for part in parts:
        hasher.update(len(part).to_bytes(8, "big"))
        hasher.update(part)
    return hasher.digest()


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


@dataclass(frozen=True, slots=True)
class _Context:
    parameters: SerializedData
    parameters_digest: bytes
    n: int
    q: int
    eta: int
    message_bits: int


@dataclass(frozen=True, slots=True)
class _Challenge:
    nonce: bytes
    u_raw: bytes
    u: np.ndarray
    v_raw: bytes
    v: np.ndarray
    commitment: bytes


class RingLWEProtocol(AuthProtocol):
    protocol_id = "ring_lwe"

    @property
    def name(self) -> str:
        return self.protocol_id

    def default_parameters(self) -> SerializedData:
        return {
            "n": _DEFAULT_N,
            "q": _DEFAULT_Q,
            "eta": _DEFAULT_ETA,
            "message_bits": _DEFAULT_MESSAGE_BITS,
            **_fixed_parameters(),
        }

    def resolve_parameters(self, overrides: SerializedData | None = None) -> SerializedData:
        overrides = _require_mapping({} if overrides is None else overrides, "Los parámetros")
        defaults = self.default_parameters()
        unknown = set(overrides) - set(defaults)
        if unknown:
            raise InvalidProtocolDataError(f"Parámetros ring_lwe desconocidos: {sorted(unknown)}.")

        fixed = _fixed_parameters()
        for key, expected in fixed.items():
            if key in overrides and overrides[key] != expected:
                raise InvalidProtocolDataError(f"'{key}' está fijado a {expected!r} en ring_lwe.")

        n = _require_int(overrides.get("n", defaults["n"]), "n", _MIN_N, _MAX_N)
        q = _require_int(overrides.get("q", defaults["q"]), "q", 3, codec.MAX_ENCODABLE_MODULUS)
        eta = _require_int(overrides.get("eta", defaults["eta"]), "eta", 1, 8)
        message_bits = _require_int(
            overrides.get("message_bits", defaults["message_bits"]),
            "message_bits",
            _MIN_MESSAGE_BITS,
            _MAX_MESSAGE_BITS,
        )
        if not _is_power_of_two(n):
            raise InvalidProtocolDataError("'n' debe ser una potencia de dos para R_q = Z_q[x]/(x^n+1).")
        if message_bits % 8:
            raise InvalidProtocolDataError("'message_bits' debe ser múltiplo de 8.")
        if message_bits > n:
            raise InvalidProtocolDataError("'message_bits' no puede superar 'n'.")

        # Centered-binomial variance is eta/2.  The decryption noise is roughly
        # e*r + e2 - e1*s; this engineering margin protects correctness but is
        # deliberately not presented as a security estimate.
        noise_std = math.sqrt((n * eta * eta / 2.0) + (eta / 2.0))
        if q // 4 <= _CORRECTNESS_MARGIN_SIGMAS * noise_std:
            raise InvalidProtocolDataError(
                "q es demasiado pequeño para n y eta: el margen de corrección Ring-LWE es insuficiente."
            )

        return {"n": n, "q": q, "eta": eta, "message_bits": message_bits, **fixed}

    def _context(self, system_parameters: SerializedData) -> _Context:
        system_parameters = _require_mapping(system_parameters, "Los parámetros del sistema")
        if _field(system_parameters, "protocol", "los parámetros del sistema") != self.protocol_id:
            raise InvalidProtocolDataError("Los parámetros del sistema pertenecen a otro protocolo.")
        parameters = _require_mapping(_field(system_parameters, "parameters", "los parámetros del sistema"), "'parameters'")
        if self.resolve_parameters(parameters) != parameters:
            raise InvalidProtocolDataError("Los parámetros del sistema no son el conjunto efectivo completo.")
        canonical = json.dumps(parameters, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return _Context(
            parameters=parameters,
            parameters_digest=_digest(_DOMAIN, b"parameters", canonical),
            n=parameters["n"], q=parameters["q"], eta=parameters["eta"],
            message_bits=parameters["message_bits"],
        )

    @staticmethod
    def _polynomial(container: SerializedData, field_name: str, label: str, context: _Context) -> tuple[bytes, np.ndarray]:
        container = _require_mapping(container, label)
        raw, polynomial = codec.decode_coefficient_bytes(
            _field(container, field_name, label), field_name, (context.n,), context.q
        )
        return raw, polynomial.astype(np.int64)

    @staticmethod
    def _decode_small_secret(value: Any, context: _Context) -> np.ndarray:
        encoded = codec.decode_coefficients(value, "s", (context.n,), context.q)
        centered = np.where(encoded > context.q // 2, encoded - context.q, encoded)
        if np.any(np.abs(centered) > context.eta):
            raise InvalidProtocolDataError("'s' contiene coeficientes fuera de la distribución configurada.")
        return centered.astype(np.int64)

    def _public_key_digest(self, context: _Context, b_raw: bytes) -> bytes:
        return _digest(_DOMAIN, b"public-key", context.parameters_digest, b_raw)

    def _encrypt_message(self, context: _Context, a: np.ndarray, b: np.ndarray,
                         public_key_digest: bytes, nonce: bytes, message: bytes) -> tuple[np.ndarray, np.ndarray]:
        seed = _digest(_DOMAIN, b"encryption-randomness", public_key_digest, nonce, message)
        r = sampling.derive_centered_binomial(_digest(seed, b"r"), (context.n,), context.eta)
        e1 = sampling.derive_centered_binomial(_digest(seed, b"e1"), (context.n,), context.eta)
        e2 = sampling.derive_centered_binomial(_digest(seed, b"e2"), (context.n,), context.eta)
        encoded_message = ring.encode_message(message, context.n, context.q)
        u = (ring.negacyclic_multiply(a, r, context.q) + e1) % context.q
        v = (ring.negacyclic_multiply(b, r, context.q) + e2 + encoded_message) % context.q
        return u.astype(np.int64), v.astype(np.int64)

    def _commitment(self, context: _Context, public_key_digest: bytes, nonce: bytes,
                    u_raw: bytes, v_raw: bytes, message: bytes) -> bytes:
        return _digest(_DOMAIN, b"commitment", context.parameters_digest,
                       public_key_digest, nonce, u_raw, v_raw, message)

    def _parse_challenge(self, challenge: SerializedData, context: _Context) -> _Challenge:
        challenge = _require_mapping(challenge, "El desafío")
        nonce = codec.decode_fixed_bytes(_field(challenge, "nonce", "el desafío"), "nonce", _NONCE_BYTES)
        u_raw, u = codec.decode_coefficient_bytes(_field(challenge, "u", "el desafío"), "u", (context.n,), context.q)
        v_raw, v = codec.decode_coefficient_bytes(_field(challenge, "v", "el desafío"), "v", (context.n,), context.q)
        commitment = codec.decode_fixed_bytes(_field(challenge, "commitment", "el desafío"), "commitment", _DIGEST_BYTES)
        return _Challenge(nonce, u_raw, u.astype(np.int64), v_raw, v.astype(np.int64), commitment)

    def generate_system_parameters(self, **params: Any) -> SerializedData:
        parameters = self.resolve_parameters(params)
        a = sampling.sample_uniform_mod_q((parameters["n"],), parameters["q"])
        return {"protocol": self.protocol_id, "parameters": parameters, "a": codec.encode_coefficients(a)}

    def generate_keypair(self, system_parameters: SerializedData, **params: Any) -> KeyPair:
        context = self._context(system_parameters)
        if self.resolve_parameters(params) != context.parameters:
            raise InvalidProtocolDataError("Los parámetros de enrollment no coinciden con los del setup.")
        _, a = self._polynomial(system_parameters, "a", "los parámetros del sistema", context)
        s = sampling.sample_centered_binomial((context.n,), context.eta)
        e = sampling.sample_centered_binomial((context.n,), context.eta)
        b = (ring.negacyclic_multiply(a, s, context.q) + e) % context.q
        encoded_b = codec.encode_coefficients(b)
        return ({"b": encoded_b}, {"s": codec.encode_coefficients(s % context.q), "b": encoded_b})

    def generate_challenge(self, system_parameters: SerializedData, public_key: SerializedData) -> SerializedData:
        context = self._context(system_parameters)
        _, a = self._polynomial(system_parameters, "a", "los parámetros del sistema", context)
        b_raw, b = self._polynomial(public_key, "b", "la clave pública", context)
        pk_digest = self._public_key_digest(context, b_raw)
        nonce = secrets.token_bytes(_NONCE_BYTES)
        message = secrets.token_bytes(context.message_bits // 8)
        u, v = self._encrypt_message(context, a, b, pk_digest, nonce, message)
        u_raw, v_raw = codec.coefficient_bytes(u), codec.coefficient_bytes(v)
        commitment = self._commitment(context, pk_digest, nonce, u_raw, v_raw, message)
        return {"nonce": codec.encode_bytes(nonce), "u": codec.encode_bytes(u_raw),
                "v": codec.encode_bytes(v_raw), "commitment": codec.encode_bytes(commitment)}

    def solve_challenge(self, system_parameters: SerializedData, private_key: SerializedData,
                        challenge: SerializedData) -> SerializedData:
        context = self._context(system_parameters)
        _, a = self._polynomial(system_parameters, "a", "los parámetros del sistema", context)
        private_key = _require_mapping(private_key, "La clave privada")
        s = self._decode_small_secret(_field(private_key, "s", "la clave privada"), context)
        b_raw, b = self._polynomial(private_key, "b", "la clave privada", context)
        parsed = self._parse_challenge(challenge, context)
        plaintext_poly = (parsed.v - ring.negacyclic_multiply(parsed.u, s, context.q)) % context.q
        message = ring.decode_message(plaintext_poly, context.message_bits, context.q)
        pk_digest = self._public_key_digest(context, b_raw)
        expected_u, expected_v = self._encrypt_message(context, a, b, pk_digest, parsed.nonce, message)
        expected_commitment = self._commitment(context, pk_digest, parsed.nonce,
                                               parsed.u_raw, parsed.v_raw, message)
        if not (np.array_equal(expected_u, parsed.u) and np.array_equal(expected_v, parsed.v)
                and hmac.compare_digest(expected_commitment, parsed.commitment)):
            raise InvalidProtocolDataError(
                "El desafío no es una encriptación Ring-LWE válida para esta clave; se rechaza sin revelar la desencriptación."
            )
        return {"message": codec.encode_bytes(message)}

    def verify_response(self, system_parameters: SerializedData, public_key: SerializedData,
                        challenge: SerializedData, response: SerializedData) -> bool:
        context = self._context(system_parameters)
        b_raw, _ = self._polynomial(public_key, "b", "la clave pública", context)
        parsed = self._parse_challenge(challenge, context)
        response = _require_mapping(response, "La respuesta")
        message = codec.decode_fixed_bytes(_field(response, "message", "la respuesta"), "message", context.message_bits // 8)
        expected = self._commitment(context, self._public_key_digest(context, b_raw),
                                    parsed.nonce, parsed.u_raw, parsed.v_raw, message)
        return hmac.compare_digest(expected, parsed.commitment)
