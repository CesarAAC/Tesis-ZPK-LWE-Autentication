from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Measurement:
    category: str
    operation: str
    metric_name: str
    value: float
    unit: str
    iteration: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Summary:
    category: str
    operation: str
    metric_name: str
    unit: str
    sample_count: int
    mean: float
    median: float
    stddev: float
    minimum: float
    p95: float
    p99: float
    maximum: float
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ProtocolRunResult:
    run_id: str
    protocol_name: str
    display_name: str
    parameters: dict[str, Any]
    measurements: list[Measurement]
    summaries: list[Summary]
    conformance_checks: dict[str, bool]
    status: str = "SUCCESS"
    error_message: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "protocol_name": self.protocol_name,
            "display_name": self.display_name,
            "parameters": self.parameters,
            "conformance_checks": self.conformance_checks,
            "status": self.status,
            "error_message": self.error_message,
            "measurements": [item.as_dict() for item in self.measurements],
            "summaries": [item.as_dict() for item in self.summaries],
        }


@dataclass(slots=True)
class ExperimentResult:
    experiment_id: str
    experiment_name: str
    config: dict[str, Any]
    config_sha256: str
    environment: dict[str, Any]
    git_commit: str
    git_dirty: bool
    protocol_order: list[str]
    started_at_utc: str
    finished_at_utc: str
    protocol_runs: list[ProtocolRunResult]

    def as_dict(self) -> dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "experiment_name": self.experiment_name,
            "config": self.config,
            "config_sha256": self.config_sha256,
            "environment": self.environment,
            "git_commit": self.git_commit,
            "git_dirty": self.git_dirty,
            "protocol_order": self.protocol_order,
            "started_at_utc": self.started_at_utc,
            "finished_at_utc": self.finished_at_utc,
            "protocol_runs": [run.as_dict() for run in self.protocol_runs],
        }
