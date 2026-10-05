"""Peikert reconciliation on Z_q, applied coefficient by coefficient.

Definitions (Peikert 2014; restated as Definitions 3-5 of Yang-Song-Guo 2025,
the source the thesis cites for this step), for w, v in Z_q:

    modular rounding   round2(v) = floor(2 v / q + 1/2) mod 2      (key bit)
    cross rounding     cross2(v) = floor(4 v / q) mod 2            (public hint)
    reconciliation     rec(w, b) = 0 if w in I_b + E (mod q), else 1

with I_0 = {0, ..., round(q/4) - 1}, I_1 = {-floor(q/4), ..., -1} and
E = [-q/8, q/8) restricted to the integers. Peikert's lemma is stated for an
even modulus: if w - v is in E then rec(w, cross2(v)) = round2(v).

Here the functions are applied directly to the odd modulus, as the thesis
writes them, without Peikert's randomized doubling into Z_2q. Consequences,
both checked exhaustively for q = 3329 by the test suite: agreement is
guaranteed for |w - v| <= 415 (some inputs already disagree at 416, although
q/8 = 416.125), and the key bit is slightly biased (1665 of the 3329 residues
round to 0).

These functions are primitives, not an authentication protocol.
"""

from __future__ import annotations

import math

import numpy as np


def modular_round(values: np.ndarray, q: int) -> np.ndarray:
    """Key bit: floor(2 v / q + 1/2) mod 2."""
    reduced = np.asarray(values, dtype=np.int64) % q
    return ((4 * reduced + q) // (2 * q)) % 2


def cross_round(values: np.ndarray, q: int) -> np.ndarray:
    """Hint bit: floor(4 v / q) mod 2 (which half of its key-bit region v lies in)."""
    reduced = np.asarray(values, dtype=np.int64) % q
    return (4 * reduced // q) % 2


def reconcile(values: np.ndarray, hint: np.ndarray, q: int) -> np.ndarray:
    """Recover round2(v) from a nearby w and the hint cross2(v)."""
    reduced = np.asarray(values, dtype=np.int64) % q
    hint = np.asarray(hint, dtype=np.int64)
    quarter_up = (q + 2) // 4            # round(q / 4), half up
    quarter_down = q // 4
    error_low = -(q // 8)                # E = [-q/8, q/8) on the integers
    error_high = math.ceil(q / 8) - 1
    low = np.where(hint == 0, error_low, error_low - quarter_down)
    high = np.where(hint == 0, quarter_up - 1 + error_high, error_high - 1)
    inside = ((reduced - low) % q) <= (high - low)
    return np.where(inside, 0, 1).astype(np.int64)


def bits_to_bytes(bits: np.ndarray) -> bytes:
    return np.packbits(np.asarray(bits, dtype=np.uint8), bitorder="little").tobytes()


def bytes_to_bits(raw: bytes, count: int) -> np.ndarray:
    bits = np.unpackbits(np.frombuffer(raw, dtype=np.uint8), bitorder="little")
    return bits[:count].astype(np.int64)
