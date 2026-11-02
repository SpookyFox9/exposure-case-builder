# Exposure Case Builder

Clusters Tenable vulnerability findings into **cases, one per finding cluster** (one vulnerability across many assets), ranks them with a transparent score, and assembles a case file with the affected assets, a timeline and the source records behind every number. Claude writes the narrative; a human analyst records the disposition. Each case exports as Markdown, CSV and JSON so it can be handed to the engineers who will fix it.

> Status: work in progress. Sections marked _TODO_ are filled in as the build lands.

## Purpose

An analyst should not have to combine dozens of per-asset reports to learn which problems matter. This tool answers "what should we fix first, and what does the fixing team need?" Output is evidence and facts, not verdicts. Every cluster number traces to source finding records. Scoring is a deterministic weighted sum with the component breakdown shown; there is no ML.

## Prerequisites

- Python >= 3.10 and [`uv`](https://docs.astral.sh/uv/)
- Claude Code (for the MCP server and the `/exposure-case` skill)
- To fetch fresh data: Tenable Vulnerability Management read-only API keys in `TENABLE_ACCESS_KEY` and `TENABLE_SECRET_KEY`

## How to run

```bash
uv sync
uv run pytest
```

_TODO:_ fetch script, sample-data quickstart, MCP configuration for Claude Code.

## Outputs

_TODO:_ cluster list, case-file and export formats; the disposition log.

## Known limitations

- The tenant has no tags and only two groups, so there is no real "owning team" field. Affected assets are grouped by OS, device type and subnet instead.
- Hostnames and IPs in the competition data are masked and are treated as opaque identifiers.
- _TODO:_ scoring limits, full-export size and timing.

## Data flows

The engine makes no network calls. The one outbound path is `scripts/fetch_tenable.py`: it reads from the Tenable API (including creating a vulnerability export job on Tenable's side) and saves the result under `data/raw/`, which is gitignored. API keys are read from environment variables only. Local writes are `record_disposition` (append-only JSONL, requires `confirm=true`) and `export_case` file output (fixed directory, requires `confirm=true`). No tool changes any external system.

## Data sources and licensing

- Tenable competition tenant: fake, masked data provided for the SWARM Global competition. A small trimmed sample is committed in `data/sample/`; full exports are not.
- Code: MIT, see `LICENSE`.
