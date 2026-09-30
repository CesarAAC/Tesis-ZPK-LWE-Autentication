from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from benchmarking.config import BenchmarkConfig
from benchmarking.export import export_experiment
from benchmarking.persistence import BenchmarkRepository
from benchmarking.runner import BenchmarkRunner
from crypto_core.registry import available_protocol_names, protocol_catalog


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Ejecuta benchmarks reproducibles de protocolos de autenticación."
    )
    parser.add_argument(
        "--config",
        default="benchmarking/configs/default.json",
        help="Archivo JSON de configuración del experimento.",
    )
    parser.add_argument(
        "--protocol",
        action="append",
        dest="protocols",
        help="ID canónico de protocolo. Puede repetirse. Por defecto usa todos los disponibles.",
    )
    parser.add_argument(
        "--output-dir",
        default="benchmark-results",
        help="Directorio para exportar JSON/CSV reproducibles.",
    )
    parser.add_argument("--notes", default=None, help="Nota libre almacenada con el experimento.")
    parser.add_argument(
        "--no-db",
        action="store_true",
        help="No persistir en PostgreSQL. Útil para pruebas; no usar para resultados oficiales.",
    )
    parser.add_argument(
        "--list-protocols",
        action="store_true",
        help="Mostrar catálogo y salir.",
    )
    return parser


def _print_catalog() -> None:
    for spec in protocol_catalog():
        state = "AVAILABLE" if spec.available else "NOT_IMPLEMENTED"
        aliases = ", ".join(spec.aliases) if spec.aliases else "-"
        print(f"{spec.protocol_id:14} {state:16} aliases={aliases}  {spec.display_name}")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.list_protocols:
        _print_catalog()
        return 0

    config = BenchmarkConfig.from_json_file(args.config)
    selected = args.protocols or list(available_protocol_names())
    runner = BenchmarkRunner(config)
    result = runner.run_experiment(selected)

    repository = None if args.no_db else BenchmarkRepository.from_environment()
    if repository is not None:
        repository.create_experiment(
            result.experiment_id,
            result.experiment_name,
            result.git_commit,
            result.git_dirty,
            result.config,
            result.config_sha256,
            result.environment,
            result.protocol_order,
            result.started_at_utc,
            result.finished_at_utc,
            args.notes,
        )
        try:
            for protocol_run in result.protocol_runs:
                repository.create_protocol_run(
                    protocol_run.run_id,
                    result.experiment_id,
                    protocol_run.protocol_name,
                    protocol_run.display_name,
                    protocol_run.parameters,
                    protocol_run.conformance_checks,
                )
                repository.save_measurements(
                    protocol_run.run_id,
                    protocol_run.measurements if config.store_raw_samples else [],
                )
                repository.save_summaries(protocol_run.run_id, protocol_run.summaries)
                repository.finish_protocol_run(protocol_run.run_id, "SUCCESS")
            repository.finish_experiment(result.experiment_id, "SUCCESS")
        except Exception:
            repository.finish_experiment(result.experiment_id, "FAILED")
            raise

    export_path = export_experiment(result, Path(args.output_dir))
    print(
        json.dumps(
            {
                "experiment_id": result.experiment_id,
                "protocols": [run.protocol_name for run in result.protocol_runs],
                "git_commit": result.git_commit,
                "git_dirty": result.git_dirty,
                "config_sha256": result.config_sha256,
                "protocol_order": result.protocol_order,
                "started_at_utc": result.started_at_utc,
                "finished_at_utc": result.finished_at_utc,
                "output": str(export_path),
                "database_persisted": repository is not None,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
