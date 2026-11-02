#!/bin/sh
# Every quality gate, cheapest first. The pre-commit hook and CI both run exactly this, so they cannot drift.
# Secret scanning is separate (gitleaks, in the pre-commit hook).
set -e
cd "$(dirname "$0")/.."

echo "== ruff (lint, import order, complexity, no print) =="
uv run ruff check src scripts tests
echo "== black (format) =="
uv run black --check -q src scripts tests
echo "== mypy (types) =="
uv run mypy
echo "== bandit (static security analysis) =="
uv run bandit -q -c pyproject.toml -r src scripts
echo "== standards (file size, function length, nesting, frozen dataclasses) =="
uv run python scripts/check_standards.py
echo "== tests with coverage (gate: 80%) =="
uv run coverage run -m pytest -q
uv run coverage report
echo "== all gates passed =="
