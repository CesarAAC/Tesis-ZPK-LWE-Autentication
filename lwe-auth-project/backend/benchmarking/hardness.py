"""Lattice problems behind each candidate and their Core-SVP estimates.

``instances`` maps the effective parameters of a protocol to the problems its
security rests on: the key (LWE in one of its variants) and the soundness of
the proof (self-target SIS in the infinity norm, as in the Dilithium
specification). ``estimate`` evaluates them with the lattice estimator
(https://github.com/malb/lattice-estimator) under the Core-SVP cost model of
Alkim, Ducas, Pöppelmann and Schwabe (ADPS16): 2^(0.292 b) classical and
2^(0.265 b) quantum for BKZ block size b.

The benchmark never calls this module. Its output is evidence for a security
assessment, stored with ``benchmarking.security_cli`` apart from the automatic
metrics. The procedure and its limits are in ``docs/estimacion-de-dureza.md``.

Modelling choices (each one is stated in the instance description):
    * Module-LWE and Ring-LWE are estimated as plain LWE of dimension k d or n;
      no known attack exploits the algebraic structure at these sizes.
    * LWR is estimated as LWE whose error is uniform over the rounding
      interval, the heuristic used by the Saber specification.
    * Soundness is the SIS instance whose solution the forking lemma or a
      self-target forger produces: [A | I | B] with the norm of an accepted
      response as bound.
"""

from __future__ import annotations

import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from crypto_core.exceptions import CryptoCoreError

ESTIMATOR_URL = "https://github.com/malb/lattice-estimator"
COST_MODEL = "Core-SVP (ADPS16): 2^(0.292 b) clásico, 2^(0.265 b) cuántico; forma GSA"


@dataclass(frozen=True, slots=True)
class LWEInstance:
    """b = A s + e mod q with s in Z^n, m samples."""

    role: str
    description: str
    n: int
    m: int
    q: int
    secret: tuple[Any, ...]
    error: tuple[Any, ...]


@dataclass(frozen=True, slots=True)
class SISInstance:
    """Find a nonzero x with ||x||_inf <= bound and M x = 0 mod q, M of size rows x columns."""

    role: str
    description: str
    rows: int
    columns: int
    q: int
    bound: int


def _cbd(eta: int) -> tuple[Any, ...]:
    return ("centered_binomial", eta)


def _uniform(low: int, high: int) -> tuple[Any, ...]:
    return ("uniform", low, high)


def instances(protocol_id: str, parameters: dict[str, Any]) -> list[LWEInstance | SISInstance]:
    """Return the instances whose hardness bounds the security of ``protocol_id``."""
    builder = _BUILDERS.get(protocol_id)
    if builder is None:
        raise CryptoCoreError(
            f"'{protocol_id}' no se basa en problemas de retículos; su seguridad se cita de la literatura."
        )
    return builder(parameters)


def _proposed(parameters: dict[str, Any]) -> list[LWEInstance | SISInstance]:
    rank, degree, eta = parameters["k_proof"], parameters["d"], parameters["eta"]
    q_proof, beta = parameters["q_proof"], parameters["beta"]
    dimension = rank * degree
    return [
        LWEInstance(
            "clave",
            f"MLWE de la clave t = A's + e: rango {rank}, grado {degree}, estimado como LWE de dimensión {dimension}",
            dimension, dimension, q_proof, _cbd(eta), _cbd(eta),
        ),
        SISInstance(
            "solidez",
            "SelfTargetMSIS sobre [A' | I | t], sin compresión de clave: cota max(gamma1 - beta, gamma2 + 1)",
            dimension, (2 * rank + 1) * degree, q_proof,
            max(parameters["gamma1"] - beta, parameters["gamma2"] + 1),
        ),
        LWEInstance(
            "transporte",
            "Cuotas del acuerdo de clave b = A s + e sobre q = 3329 (mismo tamaño que ML-KEM-768)",
            parameters["k"] * degree, parameters["k"] * degree, parameters["q"], _cbd(eta), _cbd(eta),
        ),
    ]


def _matrix_soundness(parameters: dict[str, Any], secret_bound: int, error_bound: int) -> SISInstance:
    gamma, kappa = parameters["gamma"], parameters["kappa"]
    n, m, ell = parameters["n"], parameters["m"], parameters["ell"]
    return SISInstance(
        "solidez",
        "SelfTargetSIS sobre [A | I | B]: columnas z1 (n), z2 (m) y c (ell); cota de la respuesta aceptada",
        m, n + m + ell, parameters["q"],
        max(gamma - kappa * secret_bound, gamma - kappa * error_bound),
    )


def _standard(parameters: dict[str, Any]) -> list[LWEInstance | SISInstance]:
    n, m, q, eta = parameters["n"], parameters["m"], parameters["q"], parameters["eta"]
    return [
        LWEInstance("clave", "LWE con secreto y error CBD(eta); cada columna de S es una instancia", n, m, q, _cbd(eta), _cbd(eta)),
        _matrix_soundness(parameters, eta, eta),
    ]


def _binary(parameters: dict[str, Any]) -> list[LWEInstance | SISInstance]:
    n, m, q, eta = parameters["n"], parameters["m"], parameters["q"], parameters["eta"]
    return [
        LWEInstance("clave", "LWE con secreto binario uniforme en {0, 1} y error CBD(eta)", n, m, q, _uniform(0, 1), _cbd(eta)),
        _matrix_soundness(parameters, 1, eta),
    ]


def _lwr(parameters: dict[str, Any]) -> list[LWEInstance | SISInstance]:
    n, m, q, eta = parameters["n"], parameters["m"], parameters["q"], parameters["eta"]
    half = q // (2 * parameters["p"])
    return [
        LWEInstance(
            "clave",
            f"LWR modelado como LWE con error uniforme en [{1 - half}, {half}] (error de redondeo de q a p)",
            n, m, q, _cbd(eta), _uniform(1 - half, half),
        ),
        _matrix_soundness(parameters, eta, half),
    ]


def _ring(parameters: dict[str, Any]) -> list[LWEInstance | SISInstance]:
    n, q, eta = parameters["n"], parameters["q"], parameters["eta"]
    bound = parameters["gamma"] - parameters["kappa"] * eta
    return [
        LWEInstance("clave", f"Ring-LWE de grado {n} estimado como LWE de dimensión {n}", n, n, q, _cbd(eta), _cbd(eta)),
        SISInstance(
            "solidez",
            "SelfTargetSIS sobre [a | 1 | b] en el anillo, estimado como SIS de n filas y 3n columnas",
            n, 3 * n, q, bound,
        ),
    ]


_BUILDERS = {
    "proposed_lwe": _proposed,
    "standard_lwe": _standard,
    "binary_lwe": _binary,
    "lwr": _lwr,
    "ring_lwe": _ring,
}

LITERATURE = {
    "ecdsa": {
        "classical_security_bits": 128.0,
        "quantum_security_bits": 0.0,
        "source": "NIST SP 800-57 Parte 1 rev. 5 (P-256: 128 bits clásicos); el algoritmo de Shor lo rompe en tiempo polinomial",
    },
}


# -- estimation (needs the lattice estimator) -------------------------------------


def load_estimator(path: str | Path) -> Any:
    """Import the lattice estimator from a checkout at ``path``."""
    if not (Path(path) / "estimator").is_dir():
        raise CryptoCoreError(
            f"No se encontró el lattice estimator en '{path}'. Clónelo desde {ESTIMATOR_URL}."
        )
    path = str(Path(path))
    if path not in sys.path:
        sys.path.insert(0, path)
    try:
        import estimator  # type: ignore[import-not-found]
    except ImportError as exc:
        raise CryptoCoreError(
            f"No se encontró el lattice estimator en '{path}'. Clónelo desde {ESTIMATOR_URL}."
        ) from exc
    return estimator


def _distribution(estimator: Any, spec: tuple[Any, ...]) -> Any:
    if spec[0] == "centered_binomial":
        return estimator.ND.CenteredBinomial(spec[1])
    if spec[0] == "uniform":
        return estimator.ND.Uniform(spec[1], spec[2])
    raise CryptoCoreError(f"Distribución desconocida: {spec!r}.")


def _log2(value: Any) -> float | None:
    from sage.all import RR, oo  # type: ignore[import-not-found]

    return None if value == oo else float(RR(value).log(2))


def estimate(estimator: Any, instance: LWEInstance | SISInstance) -> dict[str, Any]:
    """Core-SVP estimate of one instance: per attack, block size and log2 cost."""
    from estimator.reduction import ADPS16  # type: ignore[import-not-found]
    from sage.all import oo  # type: ignore[import-not-found]

    models = {"classical": ADPS16("classical"), "quantum": ADPS16("quantum")}
    attacks: dict[str, dict[str, Any]] = {}
    if isinstance(instance, LWEInstance):
        params = estimator.LWE.Parameters(
            n=instance.n,
            q=instance.q,
            Xs=_distribution(estimator, instance.secret),
            Xe=_distribution(estimator, instance.error),
            m=instance.m,
        )
        runs = {
            "usvp": lambda model: estimator.LWE.primal_usvp(params, red_cost_model=model, red_shape_model="gsa"),
            "dual_hybrid": lambda model: estimator.LWE.dual_hybrid(params, red_cost_model=model),
        }
    else:
        params = estimator.SIS.Parameters(
            n=instance.rows,
            q=instance.q,
            length_bound=instance.bound,
            m=instance.columns,
            norm=oo,
        )
        runs = {"sis_lattice": lambda model: estimator.SIS.lattice(params, red_cost_model=model)}
    for name, run in runs.items():
        costs = {mode: run(model) for mode, model in models.items()}
        attacks[name] = {
            "beta": int(costs["classical"]["beta"]),
            "classical_bits": _log2(costs["classical"]["rop"]),
            "quantum_bits": _log2(costs["quantum"]["rop"]),
        }
    best = min(attacks, key=lambda name: attacks[name]["classical_bits"] or float("inf"))
    return {
        "instance": asdict(instance),
        "attacks": attacks,
        "best_attack": best,
        "beta": attacks[best]["beta"],
        "classical_bits": attacks[best]["classical_bits"],
        "quantum_bits": min(
            value["quantum_bits"] for value in attacks.values() if value["quantum_bits"] is not None
        ),
    }
