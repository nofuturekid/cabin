.PHONY: check test lint format run docker-smoke

check: ## everything CI runs: format check, lint, types, tests
	uv run ruff format --check .
	uv run ruff check .
	uv run mypy
	uv run pytest

test:
	uv run pytest

lint:
	uv run ruff check .

format:
	uv run ruff format .

run:
	uv run cabin

docker-smoke: ## build the container image and check it serves /healthz
	./scripts/docker-smoke.sh
