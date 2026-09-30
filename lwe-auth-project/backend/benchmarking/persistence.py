from __future__ import annotations

import json
import os
from collections.abc import Iterable
from typing import Any

from benchmarking.types import Measurement, Summary


class BenchmarkPersistenceError(RuntimeError):
    pass


class BenchmarkRepository:
    """PostgreSQL persistence for reproducible benchmark experiments."""

    def __init__(self, database_url: str) -> None:
        self.database_url = database_url

    @classmethod
    def from_environment(cls) -> "BenchmarkRepository":
        database_url = os.getenv("DATABASE_URL")
        if not database_url:
            raise BenchmarkPersistenceError(
                "DATABASE_URL no está configurada. Use --no-db solo para pruebas locales."
            )
        return cls(database_url)

    def _connect(self):
        try:
            import psycopg
        except ImportError as exc:
            raise BenchmarkPersistenceError(
                "psycopg no está instalado en el entorno de ejecución."
            ) from exc
        return psycopg.connect(self.database_url)

    def create_experiment(
        self,
        experiment_id: str,
        name: str,
        git_commit: str,
        git_dirty: bool,
        config: dict[str, Any],
        config_sha256: str,
        environment: dict[str, Any],
        protocol_order: list[str],
        started_at_utc: str,
        finished_at_utc: str,
        notes: str | None,
    ) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO benchmark_experiments (
                    id, name, git_commit, git_dirty, config, config_sha256,
                    environment, protocol_order, client_started_at, client_finished_at,
                    notes, status
                ) VALUES (
                    %s, %s, %s, %s, %s::jsonb, %s, %s::jsonb, %s::jsonb,
                    %s::timestamptz, %s::timestamptz, %s, 'RUNNING'
                )
                """,
                (
                    experiment_id,
                    name,
                    git_commit,
                    git_dirty,
                    json.dumps(config),
                    config_sha256,
                    json.dumps(environment),
                    json.dumps(protocol_order),
                    started_at_utc,
                    finished_at_utc,
                    notes,
                ),
            )

    def finish_experiment(self, experiment_id: str, status: str) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE benchmark_experiments
                   SET status = %s, finished_at = CURRENT_TIMESTAMP
                 WHERE id = %s
                """,
                (status, experiment_id),
            )

    def assert_run_protocol(self, run_id: str, protocol_id: str) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT protocol_name FROM benchmark_protocol_runs WHERE id = %s",
                (run_id,),
            )
            row = cursor.fetchone()
        if row is None:
            raise BenchmarkPersistenceError(
                f"No existe benchmark_protocol_runs con id '{run_id}'."
            )
        if row[0] != protocol_id:
            raise BenchmarkPersistenceError(
                f"El run '{run_id}' pertenece a '{row[0]}', no a '{protocol_id}'."
            )

    def create_protocol_run(
        self,
        run_id: str,
        experiment_id: str,
        protocol_name: str,
        display_name: str,
        parameters: dict[str, Any],
        conformance_checks: dict[str, bool],
    ) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO benchmark_protocol_runs (
                    id, experiment_id, protocol_name, display_name, parameters,
                    conformance_checks, status
                ) VALUES (%s, %s, %s, %s, %s::jsonb, %s::jsonb, 'RUNNING')
                """,
                (
                    run_id,
                    experiment_id,
                    protocol_name,
                    display_name,
                    json.dumps(parameters),
                    json.dumps(conformance_checks),
                ),
            )

    def finish_protocol_run(
        self,
        run_id: str,
        status: str,
        error_message: str | None = None,
    ) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE benchmark_protocol_runs
                   SET status = %s,
                       error_message = %s,
                       finished_at = CURRENT_TIMESTAMP
                 WHERE id = %s
                """,
                (status, error_message, run_id),
            )


    def save_protocol_assessment(
        self,
        run_id: str,
        protocol_id: str,
        records: Iterable[tuple[str, str, Any, str]],
        source: str | None = None,
    ) -> None:
        rows = [
            (
                run_id,
                dimension,
                criterion,
                json.dumps(value),
                evidence,
                source,
            )
            for dimension, criterion, value, evidence in records
        ]
        if not rows:
            return
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT protocol_name FROM benchmark_protocol_runs WHERE id = %s",
                (run_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise BenchmarkPersistenceError(
                    f"No existe benchmark_protocol_runs con id '{run_id}'."
                )
            if row[0] != protocol_id:
                raise BenchmarkPersistenceError(
                    f"El assessment declara '{protocol_id}' pero el run corresponde a '{row[0]}'."
                )
            cursor.executemany(
                """
                INSERT INTO benchmark_protocol_assessments (
                    protocol_run_id, dimension, criterion, value, evidence, source
                ) VALUES (%s, %s, %s, %s::jsonb, %s, %s)
                """,
                rows,
            )

    def save_security_assessment(
        self,
        run_id: str,
        protocol_id: str,
        assessment_type: str,
        tool_or_source: str,
        tool_version: str | None,
        classical_security_bits: float | None,
        quantum_security_bits: float | None,
        assumptions: dict[str, Any],
        evidence: dict[str, Any],
    ) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT protocol_name FROM benchmark_protocol_runs WHERE id = %s",
                (run_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise BenchmarkPersistenceError(
                    f"No existe benchmark_protocol_runs con id '{run_id}'."
                )
            if row[0] != protocol_id:
                raise BenchmarkPersistenceError(
                    f"La estimación declara '{protocol_id}' pero el run corresponde a '{row[0]}'."
                )
            cursor.execute(
                """
                INSERT INTO benchmark_security_assessments (
                    protocol_run_id, assessment_type, tool_or_source, tool_version,
                    classical_security_bits, quantum_security_bits, assumptions, evidence
                ) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb)
                """,
                (
                    run_id,
                    assessment_type,
                    tool_or_source,
                    tool_version,
                    classical_security_bits,
                    quantum_security_bits,
                    json.dumps(assumptions),
                    json.dumps(evidence),
                ),
            )

    def save_measurements(
        self,
        run_id: str,
        measurements: Iterable[Measurement],
    ) -> None:
        rows = [
            (
                run_id,
                item.category,
                item.operation,
                item.metric_name,
                item.iteration,
                item.value,
                item.unit,
                json.dumps(item.metadata),
            )
            for item in measurements
        ]
        if not rows:
            return
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO benchmark_measurements (
                    protocol_run_id, category, operation, metric_name, iteration,
                    value, unit, metadata
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                """,
                rows,
            )

    def save_summaries(self, run_id: str, summaries: Iterable[Summary]) -> None:
        rows = [
            (
                run_id,
                item.category,
                item.operation,
                item.metric_name,
                item.unit,
                item.sample_count,
                item.mean,
                item.median,
                item.stddev,
                item.minimum,
                item.p95,
                item.p99,
                item.maximum,
                json.dumps(item.metadata),
            )
            for item in summaries
        ]
        if not rows:
            return
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO benchmark_summaries (
                    protocol_run_id, category, operation, metric_name, unit,
                    sample_count, mean, median, stddev, minimum, p95, p99, maximum,
                    metadata
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s::jsonb
                )
                """,
                rows,
            )
