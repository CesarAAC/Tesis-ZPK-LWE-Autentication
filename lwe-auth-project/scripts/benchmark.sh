#!/usr/bin/env bash
set -euo pipefail
# Prepare the host bind-mounted results directory for the non-root container user.
BENCHMARK_RESULTS_DIR="${BENCHMARK_RESULTS_DIR:-backend/benchmark-results}"
mkdir -p "$BENCHMARK_RESULTS_DIR"
chmod 0777 "$BENCHMARK_RESULTS_DIR"


use_database=true
for argument in "$@"; do
  if [[ "$argument" == "--no-db" ]]; then
    use_database=false
  fi
done

# Only changes inside this project invalidate an official benchmark. The Git repo may
# contain sibling thesis material unrelated to the executable experiment.
if [[ -n "$(git status --porcelain -- .)" ]]; then
  if [[ "${ALLOW_DIRTY_BENCHMARK:-0}" != "1" ]]; then
    echo "Refusing benchmark: project working tree is dirty." >&2
    echo "Commit/stash changes, or set ALLOW_DIRTY_BENCHMARK=1 for a non-official run." >&2
    exit 2
  fi
  git_dirty=true
else
  git_dirty=false
fi

git_commit="$(git rev-parse HEAD)"
host_uname="$(uname -a)"
docker_version="$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
compose_version="$(docker compose version --short 2>/dev/null || true)"
image_id="$(docker compose images -q api | head -n 1)"

if [[ -z "$image_id" ]]; then
  echo "API/benchmark image not found. Run 'docker compose build api' first." >&2
  exit 3
fi

if [[ "$use_database" == "true" ]]; then
  docker compose up -d db
  ./scripts/db-migrate.sh
fi

run_args=(docker compose run --rm -T)
if [[ -n "${BENCHMARK_CPUSET:-}" ]]; then
  run_args+=(--cpuset-cpus "${BENCHMARK_CPUSET}")
fi

"${run_args[@]}" \
  -e BENCHMARK_GIT_COMMIT="$git_commit" \
  -e BENCHMARK_GIT_DIRTY="$git_dirty" \
  -e BENCHMARK_CONTAINER_IMAGE_ID="$image_id" \
  -e BENCHMARK_HOST_UNAME="$host_uname" \
  -e BENCHMARK_DOCKER_VERSION="$docker_version" \
  -e BENCHMARK_COMPOSE_VERSION="$compose_version" \
  -e BENCHMARK_CPUSET="${BENCHMARK_CPUSET:-}" \
  benchmark sage -python -m benchmarking.cli "$@"
