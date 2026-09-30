"""Regev (2005) public-key encryption primitives over Z_q.

Shared matrix variant: A in Z_q^{m x n} is deployment material, each user holds
s in Z_q^n (distribution chosen by the caller) and publishes b = A s + e mod q.
A bit is encrypted with a binary vector r in {0, 1}^m as

    u = r^T A mod q,    v = r^T b + bit * floor(q / 2) mod q,

and decrypted from v - <u, s> = <r, e> + bit * floor(q / 2) mod q.

These functions are primitives, not an authentication protocol.
"""

from __future__ import annotations

import math

import numpy as np

# Products computed in float64 are exact while every partial sum stays below 2^53.
FLOAT64_EXACT_LIMIT = 1 << 53
INT64_LIMIT = (1 << 63) - 1


def leftover_hash_min_samples(n: int, q: int, slack_bits: int) -> int:
    """Smallest m with m >= (n + 1) * ceil(log2 q) + slack_bits.

    With fewer samples r^T A no longer hides r statistically and a ciphertext
    becomes a low-density subset-sum instance that lattice reduction can solve.
    """
    return (n + 1) * math.ceil(math.log2(q)) + slack_bits


def public_vector(
    matrix_a: np.ndarray,
    secret: np.ndarray,
    error: np.ndarray,
    q: int,
) -> np.ndarray:
    return (matrix_a.astype(np.int64) @ secret + error) % q


def encrypt_bits(
    matrix_a_float: np.ndarray,
    vector_b: np.ndarray,
    bits: np.ndarray,
    randomness: np.ndarray,
    q: int,
) -> tuple[np.ndarray, np.ndarray]:
    """Encrypt ``len(bits)`` bits; ``randomness`` has shape (len(bits), m).

    ``matrix_a_float`` is A as float64 so the dominant product uses BLAS; the
    caller guarantees m * (q - 1) < 2^53, which keeps the result exact.
    """
    u = np.rint(randomness.astype(np.float64) @ matrix_a_float).astype(np.int64) % q
    v = (randomness @ vector_b + bits * (q // 2)) % q
    return u, v


def decrypt_bits(
    u: np.ndarray,
    v: np.ndarray,
    secret: np.ndarray,
    q: int,
) -> np.ndarray:
    """Return 1 where v - <u, s> mod q is closer to floor(q/2) than to 0."""
    noisy = (v - u @ secret) % q
    return ((4 * noisy > q) & (4 * noisy < 3 * q)).astype(np.int64)
