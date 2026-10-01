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


def _centered_binomial_from_bytes(
    raw_bytes: bytes,
    shape: tuple[int, ...],
    eta: int,
) -> np.ndarray:
    """Map a bit stream to centered-binomial coefficients in [-eta, eta]."""
    count = _count(shape)
    bits_needed = 2 * eta * count
    bits = np.unpackbits(
        np.frombuffer(raw_bytes, dtype=np.uint8),
        bitorder="little",
    )[:bits_needed].reshape(count, 2 * eta)
    coefficients = bits[:, :eta].sum(axis=1) - bits[:, eta:].sum(axis=1)
    return coefficients.astype(np.int64).reshape(shape)


def sample_centered_binomial(shape: tuple[int, ...], eta: int) -> np.ndarray:
    """Sample centered-binomial coefficients using the OS CSPRNG."""
    if eta < 1:
        raise ValueError("eta must be positive")
    bits_needed = 2 * eta * _count(shape)
    return _centered_binomial_from_bytes(
        secrets.token_bytes((bits_needed + 7) // 8),
        shape,
        eta,
    )


def derive_centered_binomial(
    seed: bytes,
    shape: tuple[int, ...],
    eta: int,
) -> np.ndarray:
    """Deterministically derive centered-binomial coefficients with SHAKE-256."""
    if eta < 1:
        raise ValueError("eta must be positive")
    bits_needed = 2 * eta * _count(shape)
    stream = hashlib.shake_256(seed).digest((bits_needed + 7) // 8)
    return _centered_binomial_from_bytes(stream, shape, eta)


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


def sample_uniform_box(shape: tuple[int, ...], bound: int) -> np.ndarray:
    """Sample coefficients uniformly in [-bound, bound] with the OS CSPRNG."""
    return sample_uniform_mod_q(shape, 2 * bound + 1) - bound


def derive_sparse_ternary(seed: bytes, length: int, weight: int) -> np.ndarray:
    """Expand ``seed`` into a vector in {-1, 0, 1}^length with exactly ``weight`` nonzeros.

    Fisher-Yates placement as in Dilithium's SampleInBall, read from a
    SHAKE-256 stream: ``weight`` sign bits first, then 16-bit positions with
    rejection sampling to avoid modulo bias.
    """
    if not 0 < weight <= length < 1 << 16:
        raise ValueError("weight must be in (0, length] and length < 2^16")
    sign_bytes = (weight + 7) // 8
    stream_length = sign_bytes + 4 * weight
    stream = hashlib.shake_256(seed).digest(stream_length)
    signs = np.unpackbits(np.frombuffer(stream[:sign_bytes], dtype=np.uint8), bitorder="little")
    offset = sign_bytes
    challenge = np.zeros(length, dtype=np.int64)
    for index, position in enumerate(range(length - weight, length)):
        limit = ((1 << 16) // (position + 1)) * (position + 1)
        while True:
            if offset + 2 > len(stream):
                # SHAKE is an XOF: a longer digest extends the same stream.
                stream_length *= 2
                stream = hashlib.shake_256(seed).digest(stream_length)
            candidate = int.from_bytes(stream[offset:offset + 2], "little")
            offset += 2
            if candidate < limit:
                break
        chosen = candidate % (position + 1)
        challenge[position] = challenge[chosen]
        challenge[chosen] = 1 - 2 * int(signs[index])
    return challenge
