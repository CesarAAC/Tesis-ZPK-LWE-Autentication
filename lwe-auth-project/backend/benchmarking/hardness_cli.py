"""Estimate the hardness of every candidate with the parameters of a benchmark config.

Writes one security assessment per protocol (the format of
``configs/security.template.json``), ready for ``benchmarking.security_cli``,
plus the raw per-instance estimates. See ``docs/estimacion-de-dureza.md``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from benchmarking import hardness
from benchmarking.config import BenchmarkConfig
from benchmarking.security import SecurityAssessment
from crypto_core.registry import available_protocol_names, get_protocol

_AUTHENTICATION_ROLES = ("clave", "solidez")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Estima la dureza Core-SVP de cada candidato con el lattice estimator."
    )
    parser.add_argument("--config", default="benchmarking/configs/default.json")
    parser.add_argument("--protocol", action="append", dest="protocols")
    parser.add_argument(
        "--estimator",
        default=os.environ.get("LATTICE_ESTIMATOR_PATH", "/estimator"),
        help="Ruta a un checkout de lattice-estimator.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Directorio donde escribir un security assessment JSON por protocolo.",
    )
    return parser


def _checkout_commit(path: Path) -> str | None:
    """Commit of a git checkout, read without invoking git."""
    head = path / ".git" / "HEAD"
    if not head.is_file():
        return None
    content = head.read_text(encoding="utf-8").strip()
    if not content.startswith("ref: "):
        return content
    reference = content[5:]
    loose = path / ".git" / reference
    if loose.is_file():
        return loose.read_text(encoding="utf-8").strip()
    packed = path / ".git" / "packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="utf-8").splitlines():
            if line.endswith(" " + reference):
                return line.split(" ", 1)[0]
    return None


def _format_bits(value: float | None) -> str:
    return "inf" if value is None else f"2^{value:.1f}"


def _assess(protocol_id: str, parameters: dict[str, Any], estimator: Any) -> dict[str, Any]:
    results = [hardness.estimate(estimator, instance) for instance in hardness.instances(protocol_id, parameters)]
    authentication = [result for result in results if result["instance"]["role"] in _AUTHENTICATION_ROLES]
    weakest = min(authentication, key=lambda result: result["classical_bits"])
    return {
        "protocol_id": protocol_id,
        "parameters": parameters,
        "instances": results,
        "classical_bits": weakest["classical_bits"],
        "quantum_bits": min(result["quantum_bits"] for result in authentication),
        "limiting_instance": weakest["instance"]["role"],
    }


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    config = BenchmarkConfig.from_json_file(args.config)
    selected = args.protocols or list(available_protocol_names())
    estimator_path = Path(args.estimator)
    estimator = None
    commit = _checkout_commit(estimator_path)
    command = "python -m benchmarking.hardness_cli " + " ".join(argv if argv is not None else sys.argv[1:])
    output_dir = Path(args.output_dir) if args.output_dir else None
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    for protocol_id in selected:
        protocol = get_protocol(protocol_id)
        parameters = protocol.resolve_parameters(config.protocol_parameters.get(protocol_id, {}))
        if protocol_id in hardness.LITERATURE:
            source = hardness.LITERATURE[protocol_id]
            print(f"{protocol_id}: {source['classical_security_bits']:.0f} bits clásicos, "
                  f"{source['quantum_security_bits']:.0f} cuánticos ({source['source']})")
            assessment = SecurityAssessment(
                protocol_id=protocol_id,
                assessment_type="literature",
                tool_or_source=source["source"],
                classical_security_bits=source["classical_security_bits"],
                quantum_security_bits=source["quantum_security_bits"],
                assumptions={"parameter_set": parameters},
                evidence={"url_or_citation": source["source"]},
            )
            raw = None
        else:
            if estimator is None:
                estimator = hardness.load_estimator(estimator_path)
            raw = _assess(protocol_id, parameters, estimator)
            for result in raw["instances"]:
                instance = result["instance"]
                attacks = ", ".join(
                    f"{name} b={value['beta']} {_format_bits(value['classical_bits'])}"
                    for name, value in result["attacks"].items()
                )
                print(f"{protocol_id:13s} {instance['role']:10s} {attacks}")
            print(f"{protocol_id:13s} {'total':10s} {_format_bits(raw['classical_bits'])} clásico, "
                  f"{_format_bits(raw['quantum_bits'])} cuántico (limita: {raw['limiting_instance']})")
            assessment = SecurityAssessment(
                protocol_id=protocol_id,
                assessment_type="estimator",
                tool_or_source=f"lattice-estimator ({hardness.ESTIMATOR_URL})",
                tool_version=commit,
                classical_security_bits=round(raw["classical_bits"], 1),
                quantum_security_bits=round(raw["quantum_bits"], 1),
                assumptions={
                    "parameter_set": parameters,
                    "cost_model": hardness.COST_MODEL,
                    "notes": [result["instance"]["description"] for result in raw["instances"]],
                },
                evidence={
                    "command": command,
                    "raw_output_file": f"{protocol_id}.raw.json" if output_dir else None,
                    "url_or_citation": "docs/estimacion-de-dureza.md",
                    "notes": "Mínimo entre la clave y la solidez; la capa de transporte se informa aparte.",
                },
            )
        if output_dir:
            (output_dir / f"{protocol_id}.security.json").write_text(
                assessment.model_dump_json(indent=2), encoding="utf-8"
            )
            if raw is not None:
                (output_dir / f"{protocol_id}.raw.json").write_text(
                    json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8"
                )
    return 0


if __name__ == "__main__":
    sys.exit(main())
