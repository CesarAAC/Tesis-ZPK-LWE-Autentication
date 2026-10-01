from __future__ import annotations

import hashlib
import inspect
from pathlib import Path
from typing import Any

from benchmarking.types import Measurement
from crypto_core.interface import AuthProtocol
from crypto_core.registry import ProtocolSpec


def _protocol_source_paths(protocol: AuthProtocol) -> list[Path]:
    """Source files of the registered class and its crypto_core base classes.

    Protocols that share a template through inheritance are measured with that
    template included; the common interface is excluded because every
    candidate implements it. Helper modules that are only imported (for
    example ``crypto_core/lwe``) are not counted.
    """
    paths: list[Path] = []
    for cls in type(protocol).__mro__:
        module = cls.__module__
        if not module.startswith("crypto_core.") or module == "crypto_core.interface":
            continue
        source = inspect.getsourcefile(cls)
        if source and Path(source) not in paths:
            paths.append(Path(source))
    return paths


def collect_implementation_metrics(
    protocol: AuthProtocol,
    spec: ProtocolSpec,
    effective_parameters: dict[str, Any],
) -> list[Measurement]:
    """Collect objective implementation indicators without turning them into a score."""
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

    source_paths = _protocol_source_paths(protocol)
    if not source_paths:
        return measurements

    texts: list[str] = []
    file_bytes = 0
    try:
        for source_path in source_paths:
            texts.append(source_path.read_text(encoding="utf-8"))
            file_bytes += source_path.stat().st_size
    except OSError:
        return measurements

    source_lines = [
        line
        for text in texts
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    file_metadata = {
        **metadata,
        "source_file": source_paths[0].name,
        "source_files": [path.name for path in source_paths],
        "source_sha256": hashlib.sha256("".join(texts).encode("utf-8")).hexdigest(),
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
