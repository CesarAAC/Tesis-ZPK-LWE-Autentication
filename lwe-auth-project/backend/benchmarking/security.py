from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, model_validator


class SecurityAssessment(BaseModel):
    schema_version: int = 1
    protocol_id: str = Field(min_length=1)
    assessment_type: str = Field(min_length=1)
    tool_or_source: str = Field(min_length=1)
    tool_version: str | None = None
    classical_security_bits: float | None = Field(default=None, ge=0)
    quantum_security_bits: float | None = Field(default=None, ge=0)
    assumptions: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def require_a_security_result(self) -> "SecurityAssessment":
        if self.classical_security_bits is None and self.quantum_security_bits is None:
            raise ValueError(
                "Debe registrarse al menos una estimación de seguridad clásica o cuántica."
            )
        return self

    def assert_ready_for_persistence(self) -> None:
        if self.protocol_id.startswith("REPLACE_"):
            raise ValueError("Reemplace protocol_id antes de persistir el assessment.")
        meaningful_evidence = any(
            value not in (None, "", [], {}) for value in self.evidence.values()
        )
        if not meaningful_evidence:
            raise ValueError(
                "La estimación de seguridad debe conservar evidencia reproducible o una cita."
            )

    @classmethod
    def from_json_file(cls, path: str | Path) -> "SecurityAssessment":
        with Path(path).open("r", encoding="utf-8") as handle:
            return cls.model_validate(json.load(handle))
