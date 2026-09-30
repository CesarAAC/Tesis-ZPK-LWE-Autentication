from __future__ import annotations

import json
import math
import statistics

from benchmarking.types import Measurement, Summary


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        raise ValueError("No se puede calcular un percentil sin observaciones.")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]

    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def summarize_measurements(measurements: list[Measurement]) -> list[Summary]:
    groups: dict[tuple[str, str, str, str, str], list[float]] = {}
    metadata_lookup: dict[tuple[str, str, str, str, str], dict] = {}

    for measurement in measurements:
        if measurement.iteration is None:
            continue
        metadata_key = json.dumps(
            measurement.metadata,
            sort_keys=True,
            separators=(",", ":"),
        )
        key = (
            measurement.category,
            measurement.operation,
            measurement.metric_name,
            measurement.unit,
            metadata_key,
        )
        groups.setdefault(key, []).append(measurement.value)
        metadata_lookup[key] = measurement.metadata

    summaries: list[Summary] = []
    for key, values in sorted(groups.items()):
        category, operation, metric_name, unit, _ = key
        summaries.append(
            Summary(
                category=category,
                operation=operation,
                metric_name=metric_name,
                unit=unit,
                sample_count=len(values),
                mean=statistics.fmean(values),
                median=statistics.median(values),
                stddev=statistics.stdev(values) if len(values) > 1 else 0.0,
                minimum=min(values),
                p95=_percentile(values, 0.95),
                p99=_percentile(values, 0.99),
                maximum=max(values),
                metadata=metadata_lookup[key],
            )
        )
    return summaries
