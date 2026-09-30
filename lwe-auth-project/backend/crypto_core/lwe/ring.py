"""Small Ring-LWE arithmetic helpers for R_q = Z_q[x]/(x^n + 1)."""
from __future__ import annotations
import numpy as np


def negacyclic_multiply(left: np.ndarray, right: np.ndarray, q: int) -> np.ndarray:
    left = np.asarray(left, dtype=np.int64)
    right = np.asarray(right, dtype=np.int64)
    if left.ndim != 1 or right.ndim != 1 or left.shape != right.shape:
        raise ValueError("Ring operands must be one-dimensional polynomials of equal length.")
    n = left.size
    convolution = np.convolve(left, right)
    result = convolution[:n].astype(np.int64, copy=True)
    if n > 1:
        result[: n - 1] -= convolution[n:]
    return result % q


def encode_message(message: bytes, n: int, q: int) -> np.ndarray:
    bits = np.unpackbits(np.frombuffer(message, dtype=np.uint8), bitorder="little").astype(np.int64)
    if bits.size > n:
        raise ValueError("Message does not fit in the ring polynomial.")
    encoded = np.zeros(n, dtype=np.int64)
    encoded[: bits.size] = bits * (q // 2)
    return encoded


def decode_message(polynomial: np.ndarray, message_bits: int, q: int) -> bytes:
    noisy = np.asarray(polynomial, dtype=np.int64)[:message_bits] % q
    bits = ((4 * noisy > q) & (4 * noisy < 3 * q)).astype(np.uint8)
    return np.packbits(bits, bitorder="little").tobytes()
