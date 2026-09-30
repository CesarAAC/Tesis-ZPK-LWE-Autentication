from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from pydantic import BaseModel, Field


class AssessmentCriterion(BaseModel):
    value: Any = None
    evidence: str = ""


class ProtocolAssessment(BaseModel):
    schema_version: int = 1
    protocol_id: str = Field(min_length=1)
    implementation: dict[str, AssessmentCriterion] = Field(default_factory=dict)
    operational: dict[str, AssessmentCriterion] = Field(default_factory=dict)
    trust_architecture: dict[str, AssessmentCriterion] = Field(default_factory=dict)
    maturity: dict[str, AssessmentCriterion] = Field(default_factory=dict)
    security: dict[str, AssessmentCriterion] = Field(default_factory=dict)

    @classmethod
    def from_json_file(cls, path: str | Path) -> "ProtocolAssessment":
        with Path(path).open("r", encoding="utf-8") as handle:
            return cls.model_validate(json.load(handle))

    def records(self) -> Iterator[tuple[str, str, Any, str]]:
        for dimension in (
            "implementation",
            "operational",
            "trust_architecture",
            "maturity",
            "security",
        ):
            criteria: dict[str, AssessmentCriterion] = getattr(self, dimension)
            for criterion, item in criteria.items():
                yield dimension, criterion, item.value, item.evidence
    def assert_ready_for_persistence(self) -> None:
        if self.protocol_id.startswith("REPLACE_"):
            raise ValueError("Reemplace protocol_id antes de persistir el assessment.")
        incomplete: list[str] = []
        for dimension, criterion, value, evidence in self.records():
            if value is None or not evidence.strip():
                incomplete.append(f"{dimension}.{criterion}")
        if incomplete:
            raise ValueError(
                "El assessment contiene criterios sin valor/evidencia: "
                + ", ".join(incomplete)
            )
