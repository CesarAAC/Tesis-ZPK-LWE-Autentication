from __future__ import annotations

import argparse
import sys

from benchmarking.persistence import BenchmarkRepository
from benchmarking.security import SecurityAssessment


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Valida y almacena una estimación de seguridad con evidencia explícita."
    )
    parser.add_argument("--run-id", required=True, help="UUID de benchmark_protocol_runs.")
    parser.add_argument("--file", required=True, help="JSON basado en security.template.json.")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validar el archivo sin escribir en PostgreSQL.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    assessment = SecurityAssessment.from_json_file(args.file)
    if args.validate_only:
        print(
            f"OK: {assessment.protocol_id}: {assessment.assessment_type} "
            f"({assessment.tool_or_source})"
        )
        return 0

    assessment.assert_ready_for_persistence()
    repository = BenchmarkRepository.from_environment()
    repository.assert_run_protocol(args.run_id, assessment.protocol_id)
    repository.save_security_assessment(
        args.run_id,
        assessment.protocol_id,
        assessment.assessment_type,
        assessment.tool_or_source,
        assessment.tool_version,
        assessment.classical_security_bits,
        assessment.quantum_security_bits,
        assessment.assumptions,
        assessment.evidence,
    )
    print(f"Stored security assessment for {assessment.protocol_id} in run {args.run_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
