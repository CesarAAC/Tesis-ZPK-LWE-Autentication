#!/usr/bin/env bash
set -euo pipefail

docker compose run --rm --no-deps -T benchmark \
  sage -python -m unittest discover -s tests -v
