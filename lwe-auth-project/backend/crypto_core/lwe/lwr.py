"""Primal Learning With Rounding helpers."""
from __future__ import annotations
import numpy as np


def round_q_to_p(values: np.ndarray, q: int, p: int) -> np.ndarray:
    values = np.asarray(values, dtype=np.int64) % q
    return ((values * p + q // 2) // q) % p


def public_vector(matrix_a: np.ndarray, secret: np.ndarray, q: int, p: int) -> np.ndarray:
    products = (matrix_a.astype(np.int64) @ secret.astype(np.int64)) % q
    return round_q_to_p(products, q, p)


def encrypt_bits(matrix_a_float: np.ndarray, vector_b: np.ndarray, bits: np.ndarray,
                 randomness: np.ndarray, q: int, p: int) -> tuple[np.ndarray, np.ndarray]:
    u = np.rint(randomness.astype(np.float64) @ matrix_a_float).astype(np.int64) % q
    v = (randomness @ vector_b + bits * (p // 2)) % p
    return u, v


def decrypt_bits(u: np.ndarray, v: np.ndarray, secret: np.ndarray, q: int, p: int) -> np.ndarray:
    inner = (u.astype(np.int64) @ secret.astype(np.int64)) % q
    rounded = round_q_to_p(inner, q, p)
    noisy = (v.astype(np.int64) - rounded) % p
    return ((4 * noisy > p) & (4 * noisy < 3 * p)).astype(np.int64)
