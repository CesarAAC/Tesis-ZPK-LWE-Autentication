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

