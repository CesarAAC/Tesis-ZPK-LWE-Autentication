from __future__ import annotations

import hashlib
import inspect
from pathlib import Path
from typing import Any

from benchmarking.types import Measurement
from crypto_core.interface import AuthProtocol
from crypto_core.registry import ProtocolSpec


def collect_implementation_metrics(
    protocol: AuthProtocol,
    spec: ProtocolSpec,
    effective_parameters: dict[str, Any],
) -> list[Measurement]:
    """Collect objective implementation indicators without turning them into a score."""
    source_path_value = inspect.getsourcefile(protocol.__class__)
    metadata = {
        "module": protocol.__class__.__module__,
        "class": protocol.__class__.__name__,
        "declared_dependencies": list(spec.declared_dependencies),
    }
    measurements = [
        Measurement(
            "implementation",
            "protocol",
            "effective_parameter_count",
            float(len(effective_parameters)),
            "count",
            None,
            metadata,
        ),
        Measurement(
            "implementation",
            "protocol",
            "declared_dependency_count",
            float(len(spec.declared_dependencies)),
            "count",
            None,
            metadata,
        ),
    ]

    if not source_path_value:
        return measurements

    source_path = Path(source_path_value)
    try:
        text = source_path.read_text(encoding="utf-8")
        file_bytes = source_path.stat().st_size
    except OSError:
        return measurements

    source_lines = [
        line
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    file_metadata = {
        **metadata,
        "source_file": source_path.name,
        "source_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }
    measurements.extend(
        [
            Measurement(
                "implementation",
                "protocol",
                "source_lines_nonblank_noncomment",
                float(len(source_lines)),
                "lines",
                None,
                file_metadata,
            ),
            Measurement(
                "implementation",
                "protocol",
                "source_file_size",
                float(file_bytes),
                "bytes",
                None,
                file_metadata,
            ),
        ]
    )
    return measurements
