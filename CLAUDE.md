# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Start here

Read `docs/PLAN.md` first. It has the full plan, the decisions already made, the build order with checkboxes, current status, and resume instructions. Continue from the first unchecked item. Update its Status section as work lands.

Insider Threat Case Builder baselines each user's activity against their peers, uses rule-based detectors to flag deviations, and assembles a case file with a timeline and the source records behind every finding. Claude writes the narrative and the human analyst records the disposition. It is being built for SWARM Global (Nov 2–6, 2026) and will be listed on the CyberAgents Exchange.

## Commands

Python >=3.10 is required (the machine's default `python` is 3.9; use `uv`).

```bash
uv sync                                    # create .venv with pinned deps
uv run pytest                              # all tests
uv run pytest tests/test_x.py::test_name   # single test
uv run python scripts/mcp_smoke.py         # throwaway MCP stdio smoke server (delete after the Claude Code check)
```

There is no lint or build command yet; add them here when they exist.

## Architecture

A deterministic stdlib-only engine (`src/insider_case/`: ingest, baseline, detectors, case assembly, disposition log) wrapped by a thin stdio MCP server (`server.py`), plus a Claude Code skill (`skills/insider-case/SKILL.md`) and a playbook that chain the tools. Code scores and collects evidence, Claude narrates, the human decides. Tool schemas, detector definitions and the SKILL.md outline are in `docs/PLAN.md`.

The MCP server uses `mcp==2.3.0`. In 2.x, `FastMCP` was renamed: use `from mcp.server.mcpserver import MCPServer`. Older tutorials will not work.

## Hard rules

- Every finding must carry the source records that triggered it.
- Output is evidence and facts, not verdicts. No HR or disciplinary recommendations anywhere (code, prompts, skill text).
- Read-only by default. The only write is `record_disposition`: a local append-only JSONL log that requires `confirm=true`. No tool changes any external system.
- No outbound network calls unless documented in the README. The CERT download script is the one planned exception.
- Synthetic or public data only. Never reference any employer or any real organization's data, policies, field names or detection content.
- Never commit raw CERT dataset files (`data/raw/`, `data/subset/` are gitignored). Ship the download script and a small synthetic sample.
- Detectors are rule-based and unit-tested. No ML. Prefer the standard library; justify each third-party dependency; pin every dependency (`mcp` is the only runtime dependency).
- A committed credential is an automatic Exchange rejection even if rotated. The `.githooks/pre-commit` gitleaks hook is on (`core.hooksPath` is set to `.githooks`); never bypass it. `gitleaks dir .` shows false positives inside `.venv`; scan the staged diff or history instead.

## Reference

The event and Exchange research doc is outside this repo, in the parent folder (`../SWARM Global 2026_ Entry Status, Rules, and a Solo Build Plan for a Security Analyst.md`). Keep it out of the public repo. Read only the section a task needs, mainly section 3 (Exchange contribution process) and section 7, Idea 1. Items marked unverified there are unverified. Check installed package versions rather than trusting version numbers in it.
