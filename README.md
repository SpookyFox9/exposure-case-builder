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

Try it on the committed sample (fake, masked tenant data), no Tenable account needed:

```bash
export EXPOSURE_CASE_DATA="$PWD/data/sample"
uv run python -m exposure_case.server      # stdio MCP server; normally started by Claude Code
```

With real data, fetch an export (the one outbound network call; keys come from the environment, never the repo)
and register the server with Claude Code:

```bash
uv run python scripts/fetch_tenable.py --out data/raw/<name>
claude mcp add exposure-case --env EXPOSURE_CASE_DATA=<absolute path to data/raw/<name>> -- uv run --directory <absolute path to this repo> python -m exposure_case.server
```

Then copy `skills/exposure-case` into your Claude skills folder. `playbooks/exposure-case-playbook.md` walks through
setup, a triage session, how to read the numbers, and troubleshooting.

**MCP tools.** Read-only: `fleet_summary`, `case_queue` (threats and backlogs as two lists), `fix_queue`, `case_file`,
`fix_package`, `findings` (real finding ids to cite). Local writes, each needing `confirm=true`: `export` with
`write=true`, and `record_disposition`. No tool accepts a file path.

## Outputs

Two views of the same findings, linked both ways (every active finding is in exactly one case and exactly one fix package):

- **Case file (security team).** Rank and score with a per-component breakdown, summary facts, the fix packages that clear it, top vulnerabilities with CVEs, affected hosts, a timeline, limitations, and an empty disposition slot. Exports: `<case>.md`, `<case>.json`, `<case>-hosts.csv`.
- **Fix package (engineers).** What to do (Tenable's own solution text, one row per distinct action with what each clears), the impact contained in the package, affected hosts, CVEs and advisory links, and the cases it relieves. Exports: `<package>.md` for tickets (hosts and actions capped, with a pointer to the full lists), `<package>.json` (complete), `<package>-hosts.csv` and `<package>-actions.csv` (complete).

Exports are deterministic (no wall-clock time) and written only on request with `confirm=true`, to a fixed directory. Tenable-supplied text is neutralized: spreadsheet formulas in CSV cells are prefixed with an apostrophe (CSV files carry a UTF-8 BOM so Excel reads non-ASCII), Markdown markup is escaped so no tag, link or image can form, advisory URLs are shown as text rather than links, and invisible or bidirectional-override characters are removed. **Markdown is the supported target.** Other markups (Slack, Jira) need their own escaping; use the JSON, which is the exact unescaped copy, as the source for those. Files are written atomically, with a short hash in each file name so two items never overwrite each other. Dispositions (`assigned`, `risk-accepted`, `false-positive`, `needs-info`) are one appended JSON line each in a local log; the latest entry per item wins. The analyst name is free text, so the log is a worklog, not an audit trail.

## Known limitations

- The tenant has no tags and only two groups, so there is no real "owning team" field. Affected assets are grouped by OS, device type and subnet instead.
- Hostnames and IPs in the competition data are masked and are treated as opaque identifiers.
- _TODO:_ scoring limits, full-export size and timing.

## Data flows

The engine and the MCP server make no network calls. The one outbound path is `scripts/fetch_tenable.py`: it reads from the Tenable API (including creating a vulnerability export job on Tenable's side) and saves the result under `data/raw/`, which is gitignored. API keys are read from environment variables only. Local writes are `record_disposition` (append-only JSONL, requires `confirm=true`) and `export_case` file output (fixed directory, requires `confirm=true`). No tool changes any external system.

## Data sources and licensing

- Tenable competition tenant: fake, masked data provided for the SWARM Global competition. A small trimmed sample is committed in `data/sample/`; full exports are not.
- Code: MIT, see `LICENSE`.
