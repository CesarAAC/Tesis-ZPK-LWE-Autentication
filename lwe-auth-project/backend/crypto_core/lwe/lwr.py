"""Primal Learning With Rounding helpers."""
from __future__ import annotations
import numpy as np


def round_q_to_p(values: np.ndarray, q: int, p: int) -> np.ndarray:
    values = np.asarray(values, dtype=np.int64) % q
    return ((values * p + q // 2) // q) % p

