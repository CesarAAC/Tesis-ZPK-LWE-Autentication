"""Samplers for LWE primitives backed by the operating system CSPRNG.

NumPy is used only for vectorized arithmetic. Every random value comes from
``secrets.token_bytes`` (or from a SHAKE-256 stream when the protocol requires
deterministic re-derivation), never from NumPy's non-cryptographic generators.
"""

from __future__ import annotations

import hashlib
import math
import secrets
from functools import lru_cache

import numpy as np

_UINT32_RANGE = 1 << 32


def _count(shape: tuple[int, ...]) -> int:
    return math.prod(shape)


def sample_uniform_mod_q(shape: tuple[int, ...], q: int) -> np.ndarray:
    """Sample coefficients uniformly in [0, q) without modulo bias."""
    count = _count(shape)
    if q & (q - 1) == 0 and q <= 1 << 16:
        raw = np.frombuffer(secrets.token_bytes(2 * count), dtype="<u2")
        return (raw.astype(np.int64) & (q - 1)).reshape(shape)

    # Rejection sampling over 32-bit words keeps the distribution exactly uniform.
    limit = (_UINT32_RANGE // q) * q
    collected: list[np.ndarray] = []
    remaining = count
    while remaining:
        request = remaining + remaining // 8 + 16
        raw = np.frombuffer(secrets.token_bytes(4 * request), dtype="<u4")
        accepted = raw[raw < limit][:remaining]
        collected.append(accepted.astype(np.int64) % q)
        remaining -= accepted.size
    return np.concatenate(collected).reshape(shape)


def sample_binary(shape: tuple[int, ...]) -> np.ndarray:
    """Sample coefficients uniformly in {0, 1}."""
    count = _count(shape)
    raw = np.frombuffer(secrets.token_bytes((count + 7) // 8), dtype=np.uint8)
    return np.unpackbits(raw, bitorder="little")[:count].astype(np.int64).reshape(shape)


@lru_cache(maxsize=16)
def _gaussian_cdt(sigma: float, tail_sigmas: int) -> tuple[int, np.ndarray]:
    bound = math.ceil(tail_sigmas * sigma)
    support = np.arange(-bound, bound + 1, dtype=np.float64)
    weights = np.exp(-(support**2) / (2.0 * sigma * sigma))
    cdf = np.cumsum(weights) / weights.sum()
    cdf.setflags(write=False)
    return bound, cdf


def sample_discrete_gaussian(
    shape: tuple[int, ...],
    sigma: float,
    tail_sigmas: int,
) -> np.ndarray:
    """Sample a discrete Gaussian rho(x) = exp(-x^2 / (2 sigma^2)) via a CDT.

    The support is truncated to |x| <= ceil(tail_sigmas * sigma). Uniform inputs
    have 53 bits of precision (float64). This is a research prototype sampler:
    it is not constant time.
    """
    bound, cdf = _gaussian_cdt(float(sigma), int(tail_sigmas))
    count = _count(shape)
    raw = np.frombuffer(secrets.token_bytes(8 * count), dtype="<u8")
    uniform = (raw >> np.uint64(11)).astype(np.float64) * (2.0**-53)
    indices = np.minimum(np.searchsorted(cdf, uniform, side="right"), 2 * bound)
    return (indices.astype(np.int64) - bound).reshape(shape)


def derive_binary_matrix(seed: bytes, shape: tuple[int, ...]) -> np.ndarray:
    """Deterministically expand ``seed`` with SHAKE-256 into a {0, 1} matrix."""
    count = _count(shape)
    stream = hashlib.shake_256(seed).digest((count + 7) // 8)
    raw = np.frombuffer(stream, dtype=np.uint8)
    return np.unpackbits(raw, bitorder="little")[:count].astype(np.int64).reshape(shape)
