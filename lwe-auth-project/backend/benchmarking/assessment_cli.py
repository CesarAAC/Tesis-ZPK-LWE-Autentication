from __future__ import annotations

import argparse
import sys

from benchmarking.assessment import ProtocolAssessment
from benchmarking.persistence import BenchmarkRepository


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Valida y almacena una evaluación cualitativa/evidenciada para un run."
    )
    parser.add_argument("--run-id", required=True, help="UUID de benchmark_protocol_runs.")
    parser.add_argument("--file", required=True, help="JSON basado en assessment.template.json.")
    parser.add_argument(
        "--source",
        default=None,
        help="Referencia del documento/commit/fuente del assessment.",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validar el archivo sin escribir en PostgreSQL.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    assessment = ProtocolAssessment.from_json_file(args.file)
    records = list(assessment.records())
    if args.validate_only:
        print(f"OK: {assessment.protocol_id}: {len(records)} criterios válidos")
        return 0

    repository = BenchmarkRepository.from_environment()
    repository.save_protocol_assessment(
        args.run_id,
        assessment.protocol_id,
        records,
        source=args.source,
    )
    print(f"Stored {len(records)} criteria for {assessment.protocol_id} in run {args.run_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
