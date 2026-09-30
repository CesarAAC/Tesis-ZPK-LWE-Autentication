.PHONY: up build test db-migrate benchmark benchmark-list down

up:
	docker compose up -d --build

build:
	docker compose build --no-cache api

test:
	./scripts/test.sh

db-migrate:
	docker compose up -d db
	./scripts/db-migrate.sh

benchmark:
	./scripts/benchmark.sh

benchmark-list:
	docker compose run --rm --no-deps -T benchmark sage -python -m benchmarking.cli --list-protocols --no-db

down:
	docker compose down
