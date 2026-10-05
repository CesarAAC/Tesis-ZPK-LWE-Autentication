"""Explicit binary encodings for LWE material carried inside JSON documents.

Coefficients in Z_q (q <= 2^16) are packed as little-endian uint16 values and
Base64 encoded. Bit vectors are packed eight per byte (little-endian bit order).
The ``pack_coefficients`` family bit-packs coefficients at ceil(log2 q) bits
each (12 bits for q = 3329).
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


_WIDTH_DTYPES = {1: "<u1", 2: "<u2", 4: "<u4"}


def width_for_range(size: int) -> int:
    """Smallest supported byte width able to hold values in [0, size)."""
    for width in (1, 2, 4):
        if size <= 1 << (8 * width):
            return width
    raise ValueError("El rango excede 32 bits por coeficiente.")


def unsigned_bytes(values: np.ndarray, modulus: int) -> bytes:
    """Pack values in [0, modulus) with the narrowest little-endian width."""
    dtype = _WIDTH_DTYPES[width_for_range(modulus)]
    return np.ascontiguousarray(values, dtype=dtype).tobytes()


def encode_unsigned(values: np.ndarray, modulus: int) -> str:
    return encode_bytes(unsigned_bytes(values, modulus))


def decode_unsigned(
    value: Any,
    field_name: str,
    shape: tuple[int, ...],
    modulus: int,
) -> tuple[bytes, np.ndarray]:
    """Return raw bytes and int64 values, rejecting anything outside [0, modulus)."""
    width = width_for_range(modulus)
    count = int(np.prod(shape))
    raw = decode_fixed_bytes(value, field_name, width * count)
    values = np.frombuffer(raw, dtype=_WIDTH_DTYPES[width]).astype(np.int64).reshape(shape)
    if values.size and int(values.max()) >= modulus:
        raise InvalidProtocolDataError(
            f"'{field_name}' contiene coeficientes fuera de rango."
        )
    return raw, values


def encode_signed(values: np.ndarray, bound: int) -> str:
    """Encode values in [-bound, bound] as unsigned offsets value + bound."""
    return encode_unsigned(np.asarray(values, dtype=np.int64) + bound, 2 * bound + 1)


def decode_signed(
    value: Any,
    field_name: str,
    shape: tuple[int, ...],
    bound: int,
) -> np.ndarray:
    """Decode values in [-bound, bound]; any larger magnitude is rejected."""
    _, offsets = decode_unsigned(value, field_name, shape, 2 * bound + 1)
    return offsets - bound


def packed_bits(modulus: int) -> int:
    """Bits used per coefficient in [0, modulus) by the bit-packed encoding."""
    return max(1, (modulus - 1).bit_length())


def packed_length(count: int, modulus: int) -> int:
    """Bytes needed to bit-pack ``count`` coefficients in [0, modulus)."""
    return (count * packed_bits(modulus) + 7) // 8


def pack_coefficients(values: np.ndarray, modulus: int) -> bytes:
    """Bit-pack coefficients in [0, modulus), ceil(log2 modulus) bits each.

    Coefficients and bits are both little-endian, so q = 3329 gives the usual
    12 bits per coefficient (384 bytes for a polynomial of degree 256).
    """
    bits = packed_bits(modulus)
    flat = np.ascontiguousarray(values, dtype=np.int64).reshape(-1)
    bit_matrix = ((flat[:, None] >> np.arange(bits, dtype=np.int64)) & 1).astype(np.uint8)
    return np.packbits(bit_matrix.reshape(-1), bitorder="little").tobytes()


def unpack_coefficients(
    raw: bytes,
    field_name: str,
    shape: tuple[int, ...],
    modulus: int,
) -> np.ndarray:
    """Inverse of ``pack_coefficients``; rejects wrong lengths and values >= modulus."""
    bits = packed_bits(modulus)
    count = int(np.prod(shape))
    if len(raw) != packed_length(count, modulus):
        raise InvalidProtocolDataError(
            f"'{field_name}' debe contener exactamente {packed_length(count, modulus)} bytes."
        )
    stream = np.unpackbits(np.frombuffer(raw, dtype=np.uint8), bitorder="little")
    if stream[count * bits:].any():
        raise InvalidProtocolDataError(
            f"'{field_name}' contiene bits de relleno distintos de cero."
        )
    weights = np.left_shift(1, np.arange(bits, dtype=np.int64))
    values = stream[: count * bits].reshape(count, bits).astype(np.int64) @ weights
    if values.size and int(values.max()) >= modulus:
        raise InvalidProtocolDataError(
            f"'{field_name}' contiene coeficientes fuera de rango."
        )
    return values.reshape(shape)


def encode_packed(values: np.ndarray, modulus: int) -> str:
    return encode_bytes(pack_coefficients(values, modulus))


def decode_packed(
    value: Any,
    field_name: str,
    shape: tuple[int, ...],
    modulus: int,
) -> tuple[bytes, np.ndarray]:
    """Return the packed bytes and the coefficients of a Base64 bit-packed field."""
    raw = decode_base64(value, field_name)
    return raw, unpack_coefficients(raw, field_name, shape, modulus)
