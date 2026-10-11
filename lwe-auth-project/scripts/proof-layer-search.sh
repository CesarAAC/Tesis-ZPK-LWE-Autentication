#!/usr/bin/env bash
# Reproduce the table "Búsqueda de (k', eta')" of chapter 4 of the thesis:
# key hardness (lattice-estimator, Core-SVP) and prover acceptance per attempt.
#
#   ./scripts/proof-layer-search.sh                 # estimator in ../lattice-estimator
#   LATTICE_ESTIMATOR_DIR=/ruta ./scripts/proof-layer-search.sh
#   ./scripts/proof-layer-search.sh --without-hardness   # only the acceptance columns
set -euo pipefail

estimator_dir="${LATTICE_ESTIMATOR_DIR:-../lattice-estimator}"
estimator_commit="53da5982597709ba0fdf94ea37a84d822310fd84"

needs_estimator=true
for argument in "$@"; do
  if [[ "$argument" == "--without-hardness" ]]; then
    needs_estimator=false
  fi
done

mounts=()
if [[ "$needs_estimator" == "true" ]]; then
  if [[ ! -d "$estimator_dir/estimator" ]]; then
    echo "Clonando lattice-estimator en $estimator_dir (commit $estimator_commit)..." >&2
    git clone --quiet https://github.com/malb/lattice-estimator.git "$estimator_dir"
    git -C "$estimator_dir" checkout --quiet "$estimator_commit"
  fi
  # Docker Desktop on Windows needs the Windows path (pwd -W in Git Bash).
  host_path="$(cd "$estimator_dir" && (pwd -W 2>/dev/null || pwd))"
  mounts=(-v "$host_path:/estimator:ro")
fi

MSYS_NO_PATHCONV=1 docker compose run --rm --no-deps -T "${mounts[@]}" benchmark \
  sage -python -m benchmarking.proof_layer_search "$@"
