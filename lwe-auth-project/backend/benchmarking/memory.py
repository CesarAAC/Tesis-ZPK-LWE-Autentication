from __future__ import annotations

import threading
import time
import tracemalloc
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

import psutil

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class MemoryObservation:
    mean_rss_delta_bytes: int
    peak_rss_delta_bytes: int
    peak_python_alloc_bytes: int


class _RssSampler:
    def __init__(self, interval_ms: float) -> None:
        self._interval_seconds = interval_ms / 1000.0
        self._stop = threading.Event()
        self._process = psutil.Process()
        self.baseline = self._process.memory_info().rss
        self.peak = self.baseline
        self._sum_delta = 0
        self._samples = 0
        self._thread = threading.Thread(target=self._sample, daemon=True)

    def _sample(self) -> None:
        while not self._stop.is_set():
            try:
                current = self._process.memory_info().rss
                self.peak = max(self.peak, current)
                self._sum_delta += max(0, current - self.baseline)
                self._samples += 1
            except psutil.Error:
                return
            time.sleep(self._interval_seconds)

    def __enter__(self) -> "_RssSampler":
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        try:
            self.peak = max(self.peak, self._process.memory_info().rss)
        except psutil.Error:
            pass
        self._stop.set()
        self._thread.join(timeout=max(self._interval_seconds * 4, 0.05))


def observe_memory(
    operation: Callable[[], T],
    sample_interval_ms: float,
) -> tuple[T, MemoryObservation]:
    """Measure memory separately from timing to avoid contaminating timing samples.

    RSS sampling includes native allocations but can miss extremely short transient peaks.
    tracemalloc captures Python allocations but not all native Sage/cryptography memory.
    Both are retained because they describe different aspects of memory behavior.
    """
    tracemalloc.start()
    with _RssSampler(sample_interval_ms) as rss_sampler:
        result = operation()
    _, python_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    mean_rss_delta = (
        rss_sampler._sum_delta // rss_sampler._samples
        if rss_sampler._samples
        else 0
    )
    return result, MemoryObservation(
        mean_rss_delta_bytes=max(0, mean_rss_delta),
        peak_rss_delta_bytes=max(0, rss_sampler.peak - rss_sampler.baseline),
        peak_python_alloc_bytes=max(0, python_peak),
    )
