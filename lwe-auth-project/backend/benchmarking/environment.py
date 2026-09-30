from __future__ import annotations

import importlib.metadata
import os
import platform
import sys
from pathlib import Path
from typing import Any

import psutil


def _read_first_matching_line(path: str, prefix: str) -> str | None:
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith(prefix):
                    return line.split(":", 1)[1].strip()
    except OSError:
        return None
    return None


def _sage_version() -> str | None:
    try:
        from sage.version import version as sage_version

        return str(sage_version)
    except Exception:
        return None


def _package_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _installed_packages() -> dict[str, str]:
    packages: dict[str, str] = {}
    for distribution in importlib.metadata.distributions():
        name = distribution.metadata.get("Name")
        if name:
            packages[name.lower()] = distribution.version
    return dict(sorted(packages.items()))


def _cgroup_memory_limit_bytes() -> int | None:
    candidates = (
        Path("/sys/fs/cgroup/memory.max"),
        Path("/sys/fs/cgroup/memory/memory.limit_in_bytes"),
    )
    for path in candidates:
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value == "max":
            return None
        try:
            limit = int(value)
        except ValueError:
            continue
        if limit > 0:
            return limit
    return None


def collect_environment() -> dict[str, Any]:
    """Collect reproducibility metadata without depending on host-only tools."""
    cpu_model = _read_first_matching_line("/proc/cpuinfo", "model name")
    vm = psutil.virtual_memory()
    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_executable": sys.executable,
        "sage_version": _sage_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "container_os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
        },
        "cpu": {
            "model": cpu_model or platform.processor() or "unknown",
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
            "frequency_mhz": (
                psutil.cpu_freq().current if psutil.cpu_freq() is not None else None
            ),
        },
        "system_load": {
            "load_average": list(psutil.getloadavg()) if hasattr(psutil, "getloadavg") else None,
        },
        "process": {
            "cpu_affinity": (
                sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None
            ),
            "nice": psutil.Process().nice(),
        },
        "memory": {
            "visible_total_bytes": vm.total,
            "cgroup_limit_bytes": _cgroup_memory_limit_bytes(),
        },
        "packages": {
            "cryptography": _package_version("cryptography"),
            "fastapi": _package_version("fastapi"),
            "pydantic": _package_version("pydantic"),
            "psutil": _package_version("psutil"),
            "psycopg": _package_version("psycopg"),
        },
        "installed_python_packages": _installed_packages(),
        "runtime": {
            "container_image_id": os.getenv("BENCHMARK_CONTAINER_IMAGE_ID"),
            "host_uname": os.getenv("BENCHMARK_HOST_UNAME"),
            "docker_version": os.getenv("BENCHMARK_DOCKER_VERSION"),
            "compose_version": os.getenv("BENCHMARK_COMPOSE_VERSION"),
            "requested_cpuset": os.getenv("BENCHMARK_CPUSET") or None,
        },
    }
