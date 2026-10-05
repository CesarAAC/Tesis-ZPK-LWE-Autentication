"""High-bits / low-bits decomposition of Z_q coefficients (Dilithium's ``Decompose``).

For an even ``alpha`` that divides q - 1, every r in Z_q is written as

    r = r1 * alpha + r0 (mod q),   r0 in (-alpha/2, alpha/2],   r1 in [0, (q - 1) / alpha)

where the top interval is folded onto r1 = 0: when r - r0 = q - 1 the result
is r1 = 0 and r0 - 1, so r0 can reach -alpha/2 there. ``HighBits(r)`` is r1
and ``LowBits(r)`` is r0.

Property used by Fiat-Shamir with aborts (CRYSTALS-Dilithium specification,
round 3, Lemma 2): if ||s||_inf <= beta and ||LowBits(r)||_inf < alpha/2 - beta,
then HighBits(r + s) = HighBits(r). The test suite checks it over all of Z_q
for the parameters in use.

These functions are primitives, not an authentication protocol.
"""

from __future__ import annotations

import numpy as np


def decompose(values: np.ndarray, alpha: int, q: int) -> tuple[np.ndarray, np.ndarray]:
    """Return (HighBits, LowBits) of ``values`` mod q for the rounding step ``alpha``."""
    if alpha < 2 or alpha % 2 or (q - 1) % alpha:
        raise ValueError("alpha must be even and divide q - 1")
    reduced = np.asarray(values, dtype=np.int64) % q
    low = reduced % alpha
    low = np.where(low > alpha // 2, low - alpha, low)
    wraps = reduced - low == q - 1
    high = np.where(wraps, 0, (reduced - low) // alpha)
    low = np.where(wraps, low - 1, low)
    return high, low


def high_bits(values: np.ndarray, alpha: int, q: int) -> np.ndarray:
    return decompose(values, alpha, q)[0]


def low_bits(values: np.ndarray, alpha: int, q: int) -> np.ndarray:
    return decompose(values, alpha, q)[1]


def high_values(alpha: int, q: int) -> int:
    """Number of distinct values HighBits can take."""
    return (q - 1) // alpha
