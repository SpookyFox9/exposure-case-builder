# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Start here

Read `docs/PLAN.md` first. It has the full plan, the decisions already made, the build order with checkboxes, current status, and resume instructions. Continue from the first unchecked item. Update its Status section as work lands.

Exposure Case Builder turns Tenable vulnerability findings into **cases, one per finding cluster** (one vulnerability across many assets), ranked so a human can see what to fix first. Each case carries the evidence and an export (Markdown, CSV, JSON) an engineer on another team can act on. Claude writes the narrative and the human analyst records the disposition. It is being built for SWARM Global (Nov 2-6, 2026) and will be listed on the CyberAgents Exchange.

History: the project started as an insider-threat case builder (CERT data) and pivoted on 2026-11-02 because the competition tenant has no user-activity telemetry. The insider code is in git history (commit `56f8788` and earlier). The directory name `insider-case-builder/` is a leftover; the package is `exposure_case`.

## Commands

Python >=3.10 is required (the machine's default `python` is 3.9; use `uv`).

```bash
uv sync                                    # create .venv with pinned deps
uv run pytest                              # all tests
uv run pytest tests/test_x.py::test_name   # single test
EXPOSURE_CASE_DATA=data/sample uv run python -m exposure_case.server   # stdio MCP server on the committed sample
```

Checks run before every commit (the tools are not project dependencies; `uvx`/`uv run --with` fetch them on demand):

```bash
uvx ruff check src scripts tests --line-length 120
uvx mypy src scripts --ignore-missing-imports
uv run --with coverage coverage run --source=src/exposure_case,scripts -m pytest -q && uv run --with coverage coverage report
gitleaks git --staged --no-banner          # also runs in the pre-commit hook
```

There is no build step. Tests that spawn the MCP server use the committed `data/sample`.

## Architecture

A deterministic stdlib-only engine (`src/exposure_case/`: `ingest`, `cluster` and `fixes` build cases and fix packages, `links` joins them, `scoring`, `timeline`, `case`, `export`, `disposition`) behind `service.py` (one `Workspace` that answers every tool question as capped JSON), wrapped by a thin stdio MCP server (`server.py`), plus a Claude Code skill (`skills/exposure-case/SKILL.md`) and a playbook (`playbooks/`) that chain the tools. `tests/test_skill.py` keeps the skill in step with the server's tools. Code clusters, scores and collects evidence, Claude narrates, the human decides. Tool schemas and the scoring table are in `docs/PLAN.md`.

The MCP server uses `mcp==2.3.0`. In 2.x, `FastMCP` was renamed: use `from mcp.server.mcpserver import MCPServer`. Older tutorials will not work.

## Hard rules

- Every finding and every cluster number must trace to source records (`finding_id` + `scan.uuid`).
- Output is evidence and facts, not verdicts. No recommendation may target a person. Remediation guidance is allowed only when sourced from Tenable plugin data and labelled as such.
- The score is a transparent weighted sum with its component breakdown shown. Weights live in one documented table. No ML.
- Read-only by default. Writes are local only: `record_disposition` (append-only JSONL, requires `confirm=true`) and `export_case` file output (fixed output directory, requires `confirm=true`). No tool changes any external system.
- The one outbound network path is `scripts/fetch_tenable.py` (reads Tenable, creates an export job, writes to `data/raw/`). It is documented in the README data flows. The engine itself never calls the network.
- Data is the competition tenant: fake and masked. Treat IPs, hostnames and similar fields as opaque identifiers; never run OSINT on them (results are guaranteed misleading). Commit only a small trimmed sample in `data/sample/`; `data/raw/` (full exports) is gitignored.
- API keys come from env vars `TENABLE_ACCESS_KEY` / `TENABLE_SECRET_KEY` only, loaded from a vault outside the repo (`~/.secrets/`, DPAPI-encrypted). Never write keys to the repo, logs or tool output.
- Prefer the standard library; justify each third-party dependency; pin every dependency (`mcp` is the only runtime dependency).
- A committed credential is an automatic Exchange rejection even if rotated. The `.githooks/pre-commit` gitleaks hook is on (`core.hooksPath` is set to `.githooks`); never bypass it. `gitleaks dir .` shows false positives inside `.venv`; scan the staged diff or history instead.

## Reference

The event and Exchange research doc is outside this repo, in the parent folder (`../SWARM Global 2026_ Entry Status, Rules, and a Solo Build Plan for a Security Analyst.md`). Keep it out of the public repo. Read only the section a task needs, mainly section 3 (Exchange contribution process). Its Idea 1 (insider threat) is superseded by this pivot. Items marked unverified there are unverified. Check installed package versions rather than trusting version numbers in it.
