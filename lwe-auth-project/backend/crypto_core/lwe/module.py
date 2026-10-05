"""Module-lattice arithmetic over R_q = Z_q[x] / (x^d + 1).

A polynomial is an int64 coefficient array of length d, a vector has shape
(k, d) and a matrix (rows, columns, d). Products use the schoolbook negacyclic
convolution of ``ring.negacyclic_multiply`` (O(d^2)), not an NTT.

These functions are primitives, not an authentication protocol.
"""

from __future__ import annotations

import hashlib

import numpy as np

from crypto_core.lwe import ring


def expand_uniform_matrix(
    seed: bytes,
    rows: int,
    columns: int,
    degree: int,
    q: int,
) -> np.ndarray:
    """Deterministically expand ``seed`` into a uniform matrix in R_q^{rows x columns}.

    Entry (i, j) reads the SHAKE-128 stream of ``seed || i || j`` as
    little-endian words of 2 bytes (q up to 16 bits) or 3 bytes (q up to 24
    bits) masked to ceil(log2 q) bits and keeps the values below q (rejection
    sampling, so coefficients are exactly uniform). The byte layout is this
    project's own; it is neither Kyber's ``SampleNTT`` nor Dilithium's
    ``ExpandA``.
    """
    if not (0 < rows < 256 and 0 < columns < 256):
        raise ValueError("matrix dimensions must be in [1, 255]")
    bits = max(1, (q - 1).bit_length())
    if bits > 24:
        raise ValueError("q must fit in 24 bits")
    word_bytes = 2 if bits <= 16 else 3
    word_weights = np.left_shift(1, 8 * np.arange(word_bytes, dtype=np.int64))
    mask = (1 << bits) - 1
    matrix = np.empty((rows, columns, degree), dtype=np.int64)
    for i in range(rows):
        for j in range(columns):
            xof_input = seed + bytes([i, j])
            words = degree + degree // 2 + 32
            while True:
                stream = hashlib.shake_128(xof_input).digest(word_bytes * words)
                raw = np.frombuffer(stream, dtype=np.uint8).reshape(words, word_bytes)
                candidates = (raw.astype(np.int64) @ word_weights) & mask
                accepted = candidates[candidates < q]
                if accepted.size >= degree:
                    break
                # SHAKE is an XOF: a longer digest extends the same stream.
                words *= 2
            matrix[i, j] = accepted[:degree]
    return matrix


def transpose(matrix: np.ndarray) -> np.ndarray:
    return np.transpose(matrix, (1, 0, 2))


def centered(values: np.ndarray, q: int) -> np.ndarray:
    """Representatives in (-q/2, q/2]."""
    reduced = np.asarray(values, dtype=np.int64) % q
    return np.where(reduced > q // 2, reduced - q, reduced)


def matrix_vector(matrix: np.ndarray, vector: np.ndarray, q: int) -> np.ndarray:
    """Return matrix * vector mod q for a (rows, columns, d) matrix and a (columns, d) vector."""
    rows, columns, degree = matrix.shape
    if vector.shape != (columns, degree):
        raise ValueError("vector shape does not match the matrix")
    result = np.zeros((rows, degree), dtype=np.int64)
    for i in range(rows):
        for j in range(columns):
            result[i] += ring.negacyclic_multiply(matrix[i, j], vector[j], q)
    return result % q


def scale_vector(scalar: np.ndarray, vector: np.ndarray, q: int) -> np.ndarray:
    """Multiply every component of ``vector`` by the ring element ``scalar`` mod q."""
    return np.stack(
        [ring.negacyclic_multiply(scalar, component, q) for component in vector]
    )


def inner_product(left: np.ndarray, right: np.ndarray, q: int) -> np.ndarray:
    """Return left^T * right mod q, a single ring element."""
    if left.shape != right.shape or left.ndim != 2:
        raise ValueError("inner product needs two vectors of the same shape")
    result = np.zeros(left.shape[1], dtype=np.int64)
    for left_component, right_component in zip(left, right):
        result += ring.negacyclic_multiply(left_component, right_component, q)
    return result % q
