from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class NetworkScenario(BaseModel):
    """Synthetic network conditions used for deterministic projections."""

    name: str = Field(min_length=1)
    rtt_ms: float = Field(ge=0)
    bandwidth_mbps: float = Field(gt=0)
    description: str = ""


class BenchmarkConfig(BaseModel):
    """Configuration shared by every protocol in one benchmark experiment."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = 2
    experiment_name: str = Field(default="default-comparison", min_length=1)
    target_security_bits: int = Field(default=128, ge=1)
    warmup_iterations: int = Field(default=20, ge=0)
    timing_iterations: int = Field(default=200, ge=1)
    authentication_key_sets: int = Field(default=5, ge=1)
    memory_iterations: int = Field(default=20, ge=0)
    memory_sample_interval_ms: float = Field(default=1.0, gt=0)
    cooldown_seconds_between_protocols: float = Field(default=1.0, ge=0)
    randomize_protocol_order: bool = True
    protocol_order_seed: int = 20260930
    store_raw_samples: bool = True
    protocol_parameters: dict[str, dict[str, Any]] = Field(default_factory=dict)
    network_scenarios: list[NetworkScenario] = Field(default_factory=list)

    @field_validator("network_scenarios")
    @classmethod
    def unique_network_names(
        cls,
        scenarios: list[NetworkScenario],
    ) -> list[NetworkScenario]:
        names = [scenario.name for scenario in scenarios]
        if len(names) != len(set(names)):
            raise ValueError("Los nombres de escenarios de red deben ser únicos.")
        return scenarios

    @classmethod
    def from_json_file(cls, path: str | Path) -> "BenchmarkConfig":
        with Path(path).open("r", encoding="utf-8") as handle:
            return cls.model_validate(json.load(handle))
