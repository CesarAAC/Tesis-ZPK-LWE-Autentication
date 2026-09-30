"""Explicit binary encodings for LWE material carried inside JSON documents.

Coefficients in Z_q (q <= 2^16) are packed as little-endian uint16 values and
Base64 encoded. Bit vectors are packed eight per byte (little-endian bit order).
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

import numpy as np

from crypto_core.exceptions import InvalidProtocolDataError

MAX_ENCODABLE_MODULUS = 1 << 16


def decode_base64(value: Any, field_name: str) -> bytes:
    if not isinstance(value, str):
        raise InvalidProtocolDataError(f"'{field_name}' debe ser un string Base64.")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidProtocolDataError(
            f"'{field_name}' no contiene Base64 válido."
        ) from exc


def encode_bytes(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def decode_fixed_bytes(value: Any, field_name: str, length: int) -> bytes:
    raw = decode_base64(value, field_name)
    if len(raw) != length:
        raise InvalidProtocolDataError(
            f"'{field_name}' debe contener exactamente {length} bytes."
        )
    return raw


def coefficient_bytes(coefficients: np.ndarray) -> bytes:
    return np.ascontiguousarray(coefficients, dtype="<u2").tobytes()


def encode_coefficients(coefficients: np.ndarray) -> str:
    return encode_bytes(coefficient_bytes(coefficients))


def decode_coefficient_bytes(
    value: Any,
    field_name: str,
    shape: tuple[int, ...],
    q: int,
) -> tuple[bytes, np.ndarray]:
    """Return the raw packed bytes and the validated coefficients as uint16."""
    count = int(np.prod(shape))
    raw = decode_fixed_bytes(value, field_name, 2 * count)
    coefficients = np.frombuffer(raw, dtype="<u2").reshape(shape)
    if coefficients.size and int(coefficients.max()) >= q:
        raise InvalidProtocolDataError(
            f"'{field_name}' contiene coeficientes fuera de Z_q."
        )
    return raw, coefficients


def decode_coefficients(
    value: Any,
    field_name: str,
    shape: tuple[int, ...],
    q: int,
) -> np.ndarray:
    _, coefficients = decode_coefficient_bytes(value, field_name, shape, q)
    return coefficients.astype(np.int64)


def encode_bits(bits: np.ndarray) -> str:
    packed = np.packbits(np.asarray(bits, dtype=np.uint8), bitorder="little")
    return encode_bytes(packed.tobytes())


def decode_bits(value: Any, field_name: str, count: int) -> np.ndarray:
    raw = decode_fixed_bytes(value, field_name, (count + 7) // 8)
    bits = np.unpackbits(np.frombuffer(raw, dtype=np.uint8), bitorder="little")
    if bits[count:].any():
        raise InvalidProtocolDataError(
            f"'{field_name}' contiene bits de relleno distintos de cero."
        )
    return bits[:count].astype(np.int64)
