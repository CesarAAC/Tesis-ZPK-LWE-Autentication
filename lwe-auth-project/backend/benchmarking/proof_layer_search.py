"""Reproduce the search for the rank k' and the noise eta' of the ML-ZKAuth proof layer.

For each pair (k', eta') this computes:
    * the Core-SVP hardness of the identity key t = A's + e, with the same LWE
      instance and the same lattice-estimator calls as ``benchmarking.hardness``;
    * the probability that one prover attempt passes both rejection conditions,
      ``acceptance_probability`` of the protocol, and the mean number of attempts.

q', kappa, gamma1 and gamma2 stay at the protocol defaults and beta = eta' * kappa.
The default grid is the table "Búsqueda de (k', eta')" of chapter 4 of the thesis
(``tab:pqlite_busqueda``). Pairs outside what ``resolve_parameters`` accepts (for
instance eta' = 8, whose acceptance is below 0.05) are evaluated anyway: the search
shows why they were discarded.

Usage and Docker command: ``docs/estimacion-de-dureza.md``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from benchmarking import hardness
from crypto_core.protocols.proposed_lwe import ProposedLWEAuthProtocol, acceptance_probability

DEFAULT_GRID: tuple[tuple[int, int], ...] = (
    (3, 2), (4, 2), (4, 4), (4, 5), (4, 6), (4, 7), (4, 8), (5, 2),
)


def search_parameters(rank: int, eta: int) -> dict[str, Any]:
    """Default parameters of the protocol with k' = rank, eta' = eta and the derived beta."""
    parameters = dict(ProposedLWEAuthProtocol().resolve_parameters({}))
    parameters.update(k_proof=rank, eta_proof=eta, beta=eta * parameters["kappa"])
    return parameters


def evaluate(rank: int, eta: int, estimator: Any | None = None) -> dict[str, Any]:
    """One row of the search; the hardness columns are None without an estimator."""
    parameters = search_parameters(rank, eta)
    acceptance = acceptance_probability(rank, parameters["gamma1"], parameters["gamma2"], parameters["beta"])
    row: dict[str, Any] = {
        "k_proof": rank,
        "eta_proof": eta,
        "beta": parameters["beta"],
        "acceptance_probability": acceptance,
        "mean_attempts": 1 / acceptance,
        "key_attack": None,
        "key_block_size": None,
        "key_classical_bits": None,
        "key_quantum_bits": None,
    }
    if estimator is not None:
        key = next(instance for instance in hardness.instances("proposed_lwe", parameters) if instance.role == "clave")
        result = hardness.estimate(estimator, key)
        row.update(
            key_attack=result["best_attack"],
            key_block_size=result["beta"],
            key_classical_bits=result["classical_bits"],
            key_quantum_bits=result["quantum_bits"],
        )
    return row


def _parse_grid(text: str) -> list[tuple[int, int]]:
    pairs = []
    for item in text.split(","):
        rank, _, eta = item.partition(":")
        pairs.append((int(rank), int(eta)))
    return pairs


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Reproduce la búsqueda del rango k' y del ruido eta' de la capa de prueba de ML-ZKAuth "
            "(tabla del capítulo 4 de la tesis)."
        )
    )
    parser.add_argument(
        "--estimator",
        default=os.environ.get("LATTICE_ESTIMATOR_PATH", "/estimator"),
        help="Ruta a un checkout de lattice-estimator (commit 53da598).",
    )
    parser.add_argument(
        "--without-hardness",
        action="store_true",
        help="Calcula solo la probabilidad de aceptación, sin el lattice-estimator.",
    )
    parser.add_argument(
        "--grid",
        default=None,
        help="Pares k':eta' separados por comas (por defecto, los de la tesis: 3:2,4:2,4:4,...).",
    )
    parser.add_argument("--output", default=None, help="Archivo JSON donde guardar las filas.")
    return parser


def _format_bits(value: float | None) -> str:
    return "—" if value is None else f"2^{value:.1f}"


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    grid = _parse_grid(args.grid) if args.grid else list(DEFAULT_GRID)
    estimator = None if args.without_hardness else hardness.load_estimator(args.estimator)

    rows = [evaluate(rank, eta, estimator) for rank, eta in grid]
    print("| k' | eta' | beta | Clave (Core-SVP clásico / cuántico) | Bloque BKZ | Aceptación por intento | Intentos medios |")
    print("|---|---|---|---|---|---|---|")
    for row in rows:
        block = "—" if row["key_block_size"] is None else f"{row['key_attack']}, {row['key_block_size']}"
        print(
            f"| {row['k_proof']} | {row['eta_proof']} | {row['beta']} "
            f"| {_format_bits(row['key_classical_bits'])} / {_format_bits(row['key_quantum_bits'])} "
            f"| {block} | {row['acceptance_probability']:.3f} | {row['mean_attempts']:.1f} |"
        )
    if args.output:
        Path(args.output).write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
