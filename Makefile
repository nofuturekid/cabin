.PHONY: check test lint format run

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
