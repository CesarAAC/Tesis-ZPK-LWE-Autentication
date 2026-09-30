from __future__ import annotations

import csv
import json
from pathlib import Path

from benchmarking.types import ExperimentResult


def export_experiment(result: ExperimentResult, output_dir: str | Path) -> Path:
    root = Path(output_dir) / result.experiment_id
    root.mkdir(parents=True, exist_ok=False)

    with (root / "experiment.json").open("w", encoding="utf-8") as handle:
        json.dump(result.as_dict(), handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")

    with (root / "measurements.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "run_id",
                "protocol_name",
                "category",
                "operation",
                "metric_name",
                "iteration",
                "value",
                "unit",
                "metadata_json",
            ],
        )
        writer.writeheader()
        for run in result.protocol_runs:
            for item in run.measurements:
                writer.writerow(
                    {
                        "run_id": run.run_id,
                        "protocol_name": run.protocol_name,
                        "category": item.category,
                        "operation": item.operation,
                        "metric_name": item.metric_name,
                        "iteration": item.iteration,
                        "value": item.value,
                        "unit": item.unit,
                        "metadata_json": json.dumps(
                            item.metadata,
                            ensure_ascii=False,
                            sort_keys=True,
                        ),
                    }
                )

    with (root / "summaries.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "run_id",
                "protocol_name",
                "category",
                "operation",
                "metric_name",
                "unit",
                "sample_count",
                "mean",
                "median",
                "stddev",
                "minimum",
                "p95",
                "p99",
                "maximum",
                "metadata_json",
            ],
        )
        writer.writeheader()
        for run in result.protocol_runs:
            for item in run.summaries:
                writer.writerow(
                    {
                        "run_id": run.run_id,
                        "protocol_name": run.protocol_name,
                        "category": item.category,
                        "operation": item.operation,
                        "metric_name": item.metric_name,
                        "unit": item.unit,
                        "sample_count": item.sample_count,
                        "mean": item.mean,
                        "median": item.median,
                        "stddev": item.stddev,
                        "minimum": item.minimum,
                        "p95": item.p95,
                        "p99": item.p99,
                        "maximum": item.maximum,
                        "metadata_json": json.dumps(
                            item.metadata,
                            ensure_ascii=False,
                            sort_keys=True,
                        ),
                    }
                )

    return root
