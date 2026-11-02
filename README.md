# Exposure Case Builder

Turns a Tenable Vulnerability Management export into ranked **cases** (what is risky) and **fix packages** (what to do and what it clears), so a security analyst can see the most important work first and hand engineers exactly what they need. A deterministic Python engine does the clustering, scoring and evidence collection; a small stdio MCP server and a Claude Code skill let Claude write the cited narrative; the human analyst makes and records the decision. Every case and package exports as Markdown (tickets), CSV (full host and action lists) and JSON (tools).

Version 0.1.0. MIT licensed. Built for SWARM Global (Nov 2026).

## Purpose

An analyst should not have to combine dozens of per-asset reports to learn which problems matter, and the people who fix things should not have to decode a risk report. This tool answers two questions:

- **For the security team:** what is risky, and why does it rank where it does?
- **For engineers:** what do I do, what does it clear, and on which hosts?

Output is evidence and facts, not verdicts, and nothing in it recommends action against a person. Every number traces to source finding IDs. Scoring is a fixed weighted sum with the component breakdown shown for every case; there is no machine learning.

## Prerequisites

- Python 3.10 or newer and [`uv`](https://docs.astral.sh/uv/)
- Claude Code, for the MCP server and the `/exposure-case` skill
- To fetch your own data: a Tenable Vulnerability Management (cloud.tenable.com) read-only API key pair in `TENABLE_ACCESS_KEY` and `TENABLE_SECRET_KEY`. You do not need one to try the tool on the committed sample.

## How to run

```bash
uv sync
uv run pytest        # confirms the install; the MCP contract tests start the real server on the sample
```

Try it on the committed sample (fake, masked tenant data; no Tenable account needed):

```bash
export EXPOSURE_CASE_DATA="$PWD/data/sample"
uv run python -m exposure_case.server      # stdio MCP server; normally started by Claude Code
```

Register it with Claude Code (this edits your Claude config, so you run it yourself; check `claude mcp add --help` if your version orders the flags differently):

```bash
claude mcp add exposure-case --env EXPOSURE_CASE_DATA=<absolute path to data/sample> -- uv run --directory <absolute path to this repo> python -m exposure_case.server
```

Then copy `skills/exposure-case` into your Claude skills folder and ask Claude to *"triage the exposure data"*. In Claude Code, leave the `export` and `record_disposition` tools on **ask** (see Security notes).

With your own data, fetch an export first. This is the project's only outbound network call:

```bash
export TENABLE_UA_VENDOR="<your company or team name>"   # identifies your integration to Tenable
uv run python scripts/fetch_tenable.py --out data/raw/<name>
```

and point `EXPOSURE_CASE_DATA` at `data/raw/<name>`. `playbooks/exposure-case-playbook.md` walks through setup, a triage session, how to read the numbers, and troubleshooting.

**MCP tools.** Read-only: `fleet_summary`, `case_queue` (single-vulnerability *threats* and patch *backlogs* as two lists, so backlogs cannot bury threats), `fix_queue`, `case_file`, `fix_package`, and `findings` (the real finding IDs behind a case, to cite). Local writes, each needing `confirm=true`: `export` with `write=true`, and `record_disposition`. No tool accepts a file path.

Optional settings: `EXPOSURE_CASE_EXPORTS` (default `./exports`) and `EXPOSURE_CASE_DISPOSITIONS` (default `./dispositions.jsonl`); both are gitignored.

## Outputs

Two views of the same findings, linked both ways (every active finding is in exactly one case and exactly one fix package):

- **Case file (security team).** Rank and score with a per-component breakdown, summary facts, the fix packages that address it, top vulnerabilities with CVEs, affected hosts, a timeline, limitations, and an empty disposition slot. Exports: `<case>.md`, `<case>.json`, `<case>-hosts.csv`.
- **Fix package (engineers).** What to do (Tenable's own solution text, one row per distinct action with what each clears), the impact contained in the package, affected hosts, CVEs and advisory links, and the cases it relieves. Exports: `<package>.md` for tickets (hosts and actions capped, with a pointer to the full lists), `<package>.json` (complete), `<package>-hosts.csv` and `<package>-actions.csv` (complete).

A package's totals are what it **contains** across several distinct actions. Only each action's own row says what that action alone clears, and Tenable's data does not say that one update replaces another, so the tool never claims it.

Exports are deterministic (no wall-clock time) and written only on request with `confirm=true`, to a fixed directory. Tenable-supplied text is neutralized: spreadsheet formulas in CSV cells are prefixed with an apostrophe (CSV files carry a UTF-8 BOM so Excel reads non-ASCII), Markdown markup is escaped so no tag, link or image can form, advisory URLs are shown as text rather than links, and invisible or bidirectional-override characters are removed. **Markdown is the supported target.** Other markups (Slack, Jira) need their own escaping; use the JSON, which is the exact unescaped copy, as the source for those. Files are written atomically, with a short hash in each file name so two items never overwrite each other.

Dispositions (`assigned`, `risk-accepted`, `false-positive`, `needs-info`) are one appended JSON line each in a local log (capped at 5 MB); the latest entry per item wins. The analyst name is free text, so the log is a worklog, not an audit trail.

## Known limitations

- **The ranking is a judgment, not a validated model.** The weights (severity 30, exploit 25, breadth 15, volume 10, age 5, unsupported 5, recurrence 5, patch 5) are documented and adjustable in `scoring.py`, but nothing here tests them against real outcomes. CISA KEV is common in the sample tenant (793 of 10,283 active findings), so large patch families score high on the exploit component; the two-list queue exists for that reason.
- **Fix grouping is heuristic.** A package is a product (the first CPE's vendor and product) plus a fix type read from the opening verb of Tenable's solution text. Tenable's solution text is often generic ("Update the affected packages."), a few plugins have no CPE (they become their own package), and some products list dozens of separate actions that a human can see are cumulative (for example "Upgrade to OpenSSH 10.3 or later" through "10.6 or later"). The tool lists them as given rather than guessing at supersession.
- **Near-duplicate cases remain.** Plugins for the same product on the same hosts (for example several Oracle Java CPU releases) are separate cases. The fix view rolls them up; the case view does not.
- **The timeline is thin.** The export has first-found and last-found dates for every finding, but Tenable's own fixed and reopened dates for only a small minority.
- **Counts agree with Tenable, with a known gap.** On the sample tenant 4,636 of 4,677 comparable plugins (99.1%) match Tenable's own plugin counts (as distinct hosts or finding instances). The other 41 all have the export below Tenable's number; the cause is unverified.
- **Findings of severity info are not part of any case.**
- **No owner or team field.** The tenant has no tags and two groups, so a case cannot say who owns a host; host tables show host, IP, OS and counts.
- **Scope.** Tenable Vulnerability Management (cloud.tenable.com) only; Tenable Security Center and Nessus are not supported. Tested on one tenant (160 hosts, 19,437 findings: about 108 MB fetched in 30 seconds, loaded in under a second, 815 cases and 200 packages built in about one second). Larger tenants are untested; each export chunk is limited to 256 MB.
- **Developed and tested on Windows 11.** The code is portable Python, but other platforms are untested (one symlink test is skipped on Windows).
- **Narratives are Claude's.** The engine is deterministic; the cited narrative that Claude writes from it is not, and it is only as good as the skill and the analyst's review.
- Hostnames and IPs in the competition data are masked and are treated as opaque identifiers.

## Security notes

- **`confirm=true` is a convention, not proof of consent.** The server cannot tell whether a human agreed; Claude passes the flag. The real gate is your client's tool-permission prompt, so keep `export` and `record_disposition` on **ask** and do not allow-list them. The flags are strict booleans, so `"true"` or `1` is refused.
- **Tenable text is untrusted.** Plugin names, solution text, hostnames and advisory links come from outside and could contain instructions aimed at a model. The server's instructions and the skill tell Claude to treat them, and recorded disposition notes, as data, never instructions.
- **No tool accepts a file path.** The data, export and log locations are fixed when the server starts; item IDs are checked against the loaded export.
- **Secrets.** API keys are read from environment variables only, never written to disk by this project, never printed, and held in an object whose `repr` hides them. Keep them in a secret store outside the repo.

## Data flows

Every outbound destination, scope and state-changing action:

- **The engine and the MCP server make no network calls.** They read a saved export from disk.
- **`scripts/fetch_tenable.py` is the only outbound path.** It talks to `https://cloud.tenable.com` over HTTPS and nothing else, using these calls:
  - `POST /vulns/export` with `{"num_assets": 50, "filters": {"state": ["open", "reopened", "fixed"]}}`. **This creates a vulnerability export job on Tenable's side.** That is the only state change and it touches no tenant data.
  - `GET /vulns/export/{uuid}/status` and `GET /vulns/export/{uuid}/chunks/{n}`, to poll and download that job.
  - `GET /workbenches/vulnerabilities?date_range=90`, plugin-level counts used only to cross-check the export.
- **What is sent:** the API key pair in the `X-ApiKeys` header, the User-Agent below, and the request bodies above. Nothing from your environment beyond that.
- **Scope:** apart from creating the export job, the calls above only read data, so a read-only key should be enough. It was developed with a limited-permission key (one that could not read the audit log, HTTP 403); the exact minimum role Tenable requires for vulnerability exports is not verified here.
- **User-Agent:** every request sends Tenable's standard integration header, `Integration/1.0 (VENDOR; PRODUCT; Build/VERSION)` ([Tenable's User-Agent guide](https://developer.tenable.com/docs/user-agent-header)). The vendor defaults to the project name; set `TENABLE_UA_VENDOR` to your own company or team name so Tenable can tell whose integration it is.
- **Where the fetched data goes:** `data/raw/`, which is gitignored.
- **Local writes only,** each requiring `confirm=true`: export files in `EXPOSURE_CASE_EXPORTS`, and the append-only disposition log. Nothing changes any other system.
- **The model sees tool results.** When you use the MCP server through Claude Code, case and package data (hostnames, IPs, plugin names, solution text) is sent to the model provider your client is configured for. The sample and the competition tenant are fake and masked; treat real tenant data accordingly.

## Data sources and licensing

- **Tenable competition tenant:** fake, masked data provided for the SWARM Global competition. A small trimmed sample is committed in `data/sample/` (1,125 findings, 154 hosts, 50 plugins; fake and masked, with long plugin output truncated); full exports are never committed.
- **Code:** MIT, see `LICENSE`.
- **Dependencies (both MIT, both pinned):** `mcp==2.3.0` is the only runtime dependency, needed to speak the Model Context Protocol over stdio; `pytest==9.2.0` is dev-only. The engine itself uses only the Python standard library. Lint, type and coverage checks (`ruff`, `mypy`, `coverage`) are run on demand and are not project dependencies.
