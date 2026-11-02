# Exposure Case Builder: Build Plan

Living plan for the SWARM Global build (Nov 2-6, 2026). Update the **Status** section as work lands. A new session should read this file and `CLAUDE.md` first.

**Pivot (2026-11-02):** the project began as an insider-threat case builder on CERT data. The competition Tenable tenant has no user-activity telemetry (only users, assets, scans, vulnerability findings), so the build now targets vulnerability exposure. The architecture carries over; the insider code is in git history (`56f8788` and earlier).

## What we're building

One **case per finding cluster**: a vulnerability (Tenable plugin) affecting many assets. A triage queue ranks clusters so a human sees the most important work first. Each case holds the affected assets, a timeline, a score breakdown and the source records, and exports as Markdown, CSV and JSON for engineers on other teams. Claude writes the narrative; the human records the disposition.

Three components with a fixed division of labor:

1. **Deterministic Python engine** (stdlib only). Ingests a saved Tenable export, clusters, scores, assembles cases and exports. No ML.
2. **Stdio MCP server** wrapping the engine.
3. **Claude Code skill** (`/exposure-case`) plus a short playbook that chains the tools.

## Decisions made

| Decision | Choice | Why |
|---|---|---|
| Domain | Vulnerability exposure, not insider threat | Tenant data fits; no equivalent on the Exchange; user judged insider threat added needless complication |
| Case unit | Finding cluster keyed by `plugin.id` | A human acts on one fix across many assets, not 50 per-asset cases |
| Optional rollup | Group clusters by `plugin.family`/`cpe` product | Stretch goal |
| Score | Transparent weighted sum, breakdown shown, weights in one table | Explainable, no ML |
| Context fields | Optionally join VPR and CVSS from `/workbenches/vulnerabilities` by `plugin_id` | The export has neither; the workbench list is capped at 5,000 rows, so coverage is partial and the score must not depend on it |
| Team grouping | Affected assets grouped by OS, device type, /24 subnet | Tenant has no tags and only 2 groups |
| Export | Markdown handoff + CSV of affected assets + JSON bundle; text by default, file write needs `confirm=true` to a fixed directory | Shareable with other teams |
| Disposition | `record_disposition` per cluster: `assigned`, `risk-accepted`, `false-positive`, `needs-info`, plus a note | Append-only local JSONL, `confirm=true` |
| Data | Competition tenant (fake, masked); trimmed sample committed, full export gitignored | User confirmed it is all fake data |
| Fetch | Optional documented script `scripts/fetch_tenable.py`; engine reads saved files | Offline deterministic core |
| Secrets | DPAPI-encrypted file `~/.secrets/tenable.cred.xml`, loaded to env vars per session | No new dependency, nothing in the repo |
| Repo | Reuse this repo; package renamed `exposure_case` | User chose reuse |
| MCP SDK | `mcp==2.3.0` | Smoke-tested in Claude Code 2026-11-02; `from mcp.server.mcpserver import MCPServer` |
| Python | >=3.10 via `uv` | `mcp` requires >=3.10 |

## Tenable data facts (surveyed 2026-11-02, Tenable Vulnerability Management, cloud.tenable.com)

- `/users`: 75; `/groups`: 2; `/assets`: 178 (164 with vulns); `/scans`: 4 (Partner Lab, Weekly Network, BeyondTrust Advanced Agent, Daily Agent); tag values: 0.
- `/audit-log/v1/events`: HTTP 403 with the current read-only keys.
- `/workbenches/vulnerabilities`: 5000 plugin-level rows (possibly a cap, unverified) with `count`, `severity`, `vpr_score`, `cvss_base_score`, `cvss3_base_score`, `plugin_family`, `plugin_id`, `plugin_name`, `vulnerability_state`.
- `POST /vulns/export` (states open/reopened/fixed): `num_assets` is the **assets per chunk**, not a limit. The default fleet export returns 4 chunks. Full export (fetched 2026-11-02, 30 s, about 108 MB on disk): **19,437 findings, 160 assets, 7,714 plugins (7,148 clusters with non-info, non-fixed findings), 18 scans**. States: 18,448 OPEN, 604 REOPENED, 385 FIXED. Severity: 9,071 info, 4,391 medium, 3,856 high, 1,354 critical, 765 low. 3,531 have `exploit_available`, 753 `exploited_by_malware`, 192 `in_the_news`, 50 `unsupported_by_vendor`, 0 `checks_for_default_account`. `first_found` spans 2026-05-18 to 2026-11-02. There are no duplicate (asset, plugin, port, protocol) rows.
- Record keys: `finding_id`, `state`, `severity`, `first_found`, `last_found`, `asset{uuid,hostname,ipv4,operating_system,device_type,...}`, `plugin{id,name,family,synopsis,description,exploit_available,exploited_by_malware,in_the_news,has_patch,unsupported_by_vendor,checks_for_default_account,exploit_framework_*,xrefs,cpe,...}`, `port{port,protocol,service}`, `scan{uuid,started_at,schedule_uuid,target}`, `output`, `source`. No `vpr`, `cvss` or `solution` field in the export's plugin object.
- **The workbench plugin list is capped at exactly 5,000 rows**, so 3,000 of the 7,677 clusters with non-fixed findings have no workbench row. VPR is present for only 4,049 of 7,677 clusters. **The score therefore cannot depend on VPR**; VPR/CVSS are optional context shown when available.
- **Reconciliation** (distinct non-fixed assets per plugin vs workbench `count`): 4,622 of 4,677 comparable clusters match exactly; 55 do not (about 1.2%), and all 55 have the export below the workbench count (by 1 to 31). The workbench saw 164 assets with vulns, the export has 160. The cause is unverified (not just those 4 assets, since one gap is 31). Treat reconciliation as a reported tolerance, not a hard assertion.
- OS strings are highly varied (120 distinct first OS strings), so peer grouping needs normalization to an OS family. Device types: general-purpose 15,961, embedded 1,250, switch 551, unknown 428, firewall 422.
- IPs, hostnames and similar fields are masked. Never OSINT them.
- **Unverified:** where remediation text (`solution`) lives (not in the export), whether the workbench plugin list can be paged past 5,000 rows, the cause of the reconciliation gap, what the 4 assets missing from the export are.

## Constraints (from the brief)

- MIT license; public repo on a personal GitHub account (not EMU).
- No secrets anywhere in git history (automatic Exchange rejection even if rotated). The pre-commit gitleaks hook stays on.
- Read-only by default; local writes only, behind `confirm=true`; every outbound path documented in the README.
- Output is evidence and facts; no recommendation targets a person; remediation guidance only from plugin data and labelled.
- Pin every dependency; justify each third-party one. `mcp` is the single runtime dependency.
- Every cluster number carries source record IDs.

## Repo layout

```
insider-case-builder/               (directory name is a leftover; package is exposure_case)
├── LICENSE, README.md, CLAUDE.md, pyproject.toml, uv.lock
├── .githooks/pre-commit            gitleaks on staged changes
├── src/exposure_case/
│   ├── schema.py                   frozen dataclasses (Evidence, Finding)
│   ├── ingest.py                   export reader (FindingRecord, PluginInfo)
│   ├── cluster.py                  group findings by plugin
│   ├── scoring.py                  weighted components + breakdown
│   ├── case.py                     cluster case assembly and timeline
│   ├── export.py                   Markdown / CSV / JSON handoff
│   ├── disposition.py              append-only local JSONL log
│   └── server.py                   MCP stdio server (thin wrapper)
├── data/sample/                    committed sample: 1,125 findings, 154 assets, 50 plugins (data/raw/ is gitignored)
├── scripts/fetch_tenable.py        the one outbound path
├── scripts/make_sample.py          builds data/sample/ from a full export
├── skills/exposure-case/SKILL.md
├── playbooks/exposure-case-playbook.md
├── tests/
└── docs/                           PLAN.md
```

**README sections (Exchange requires):** Purpose, Prerequisites, How to run, Outputs, Known limitations, Data flows, Data sources and licensing. Tag a release (v0.1.0) and submit from the tag.

## Scoring (initial design; weights to be fixed in Phase 3 and documented here)

Components per cluster: max severity, `exploit_available`, `exploited_by_malware`, `in_the_news`, `has_patch` (patchable raises actionability), affected asset count, age (oldest `first_found`), reopened count, `unsupported_by_vendor`, `checks_for_default_account`, VPR (if joined). The case shows each component's value and contribution.

## MCP tools

| Tool | Output |
|---|---|
| `fleet_summary` | Totals, severity distribution, state counts |
| `clusters` | Ranked list: cluster ID, plugin, score, asset count, max severity, age, one-line reason; `top_n` |
| `cluster_case` | Summary, score breakdown, affected-asset table, timeline, fleet share, sample plugin output, remediation info, evidence record IDs |
| `export_case` | Markdown, CSV, JSON handoff; file writes need `confirm=true` |
| `record_disposition` | `cluster_id`, `analyst`, `disposition`, `note`, `confirm`; rejects unless `confirm=true` |

The data path comes from `EXPOSURE_CASE_DATA` or a server argument; no tool accepts arbitrary file paths.

## Testing strategy

- Unit tests per component (pytest, written first) with hand-built fixtures; every cluster asserts non-empty evidence.
- **Reconciliation test:** each cluster's asset count must match Tenable's plugin-level `count` for the same export. There is no answer key, so this is the trust check.
- Golden-file tests for the exporters.
- MCP contract tests: an SDK client spawns the stdio server, calls each tool, checks schemas and clean failure on bad input.
- Demo check: a narrative may cite only record IDs that exist in the data.
- Security gate: gitleaks on every commit; a full-history scan before the Exchange PR.

## Build order

**Phase 1: reset (Mon Nov 2 evening)**
1. [x] Rename package to `exposure_case`, remove insider code/data, generalize `Finding`
2. [x] Rewrite `CLAUDE.md`, `README.md`, this plan
3. [x] Save pivot to project memory
4. [ ] User runs `claude mcp remove insider-smoke` (leftover registration)

**Phase 2: ingest (test-first)**
1. [x] `scripts/fetch_tenable.py` (export job, polling, chunks to `data/raw/`; keys from env only); 9 tests with a fake transport
2. [x] `ingest.py` export reader and plugin-info loader; 20 tests. Full-fleet export fetched and loads in 0.6 s (19,437 records)
3. [x] `scripts/make_sample.py` and committed `data/sample/` (top 40 plugins by asset count plus 10 notable; biased to common plugins, so only 33 critical findings)
4. [x] python-reviewer pass on Phase 2 code. Fixed: server-supplied chunk IDs (path traversal), non-dict responses, malformed-record crashes in `make_sample.py` (now reuses the engine parser), invalid UTF-8 / deep-nesting / oversized files, 3.10-safe timestamps with any fraction length, `chunks_failed` detection, cleanup after a partial fetch, API keys hidden from client repr/`vars()`, key validation. Not done on purpose: 429 retry/backoff (single export job), treating duplicate `finding_id` as updates (real export has none), numeric-string ports. 87 tests pass.

**Phase 3: engine (test-first)**
1. [ ] Clustering and fleet-share comparison
2. [ ] Score components, ranking, documented weights
3. [ ] Per-cluster timeline; reconciliation test against Tenable counts

**Phase 4: case and export**
1. [ ] Case assembly
2. [ ] Markdown, CSV, JSON exporters with golden-file tests

**Phase 5: MCP, skill, playbook**
1. [ ] MCP server with five tools and contract tests
2. [ ] `SKILL.md` and playbook; demo on the sample data

**Phase 6: polish and submit**
1. [ ] Full-history secret scan, tag v0.1.0, Exchange PR (use `/cyberagents-exchange-submit`)
2. [ ] Rehearse the demo; confirm submission details at office hours

## Risks

- **High:** the score reads as arbitrary. Mitigation: breakdown, one weights table.
- **Resolved:** full export size and time (30 s, 108 MB, loads in 0.6 s).
- **High:** 7,148 clusters, so ranking quality is the product. Mitigation: documented components, hand-checked top 20 against the data.
- **Medium:** Tenable already ranks by VPR. Lead the demo with clustering, evidence, handoff export and disposition.
- **Medium:** remediation text may need another endpoint (another outbound call).
- **Medium:** time; the target is a working demo by the end of Tuesday.
- **Low:** masked identifiers; treated as opaque.

## Unverified items (do not assume)

- Official Rules were not read. Open: whether pre-existing code is allowed or work must start during the event; repo-structure, demo-video and pitch-deck requirements; data restrictions; whether all submissions or only winners must be listed on the Exchange.
- Submission deadline and pitch-selection process; assumed Wednesday, confirm at office hours.
- The Exchange repo details (`/cyberagents-exchange-submit`, `validator.py` vocabularies) came from the research doc; they were not re-fetched.
- Judging criteria and weights are unpublished. The user's priority is impact on real security work.
- Tenable items listed under "Tenable data facts".

## Status (update as work lands)

Last updated: 2026-11-02, Monday evening.

- Done: pivot decided and confirmed (finding-cluster cases, reuse repo, tenant data is fake and usable, live fetch allowed as a documented path).
- Done: Tenable keys stored in `~/.secrets/tenable.cred.xml` (DPAPI); `tenable-env.ps1` loads them per session. Survey scripts live in the session scratchpad, not the repo.
- Done (Phase 1): package renamed to `exposure_case`; insider generator, data and tests removed; `Finding` now uses `subject`; 8 tests pass; docs rewritten. Nothing is committed yet.
- Done (Phase 2): `ingest.py`, `scripts/fetch_tenable.py`, `scripts/make_sample.py`, `data/sample/` (1.3 MB, gitleaks clean). 87 tests pass. The full export lives in `data/raw/full1` (gitignored, about 108 MB). Review findings fixed. Nothing is committed yet.
- Not started: Phase 3 onward.

## Resuming in a new session

```bash
cd "C:/Users/maupi/Documents/Obsidian Vault/SWARM/insider-case-builder"
uv sync                      # create .venv with pinned deps (Python >=3.10)
uv run pytest                # run tests
```

- Read `CLAUDE.md`, then this file's Status and Build order. Continue at the first unchecked item.
- To use the Tenable API in PowerShell: `. $HOME\.secrets\tenable-env.ps1` (loads env vars for that session). To re-store keys, run `powershell -File $HOME\.secrets\tenable-store.ps1` in a real terminal, not through `!`.
- gitleaks is installed via winget (`Gitleaks.Gitleaks`). The hook runs `gitleaks git --staged`. `gitleaks dir .` reports false positives inside the gitignored `.venv`; scan the staged diff or history instead.
- The research doc lives outside the repo, in the parent folder. Keep it out. Read only section 3 (Exchange contribution process).
- Workflow reminders: write tests first; run the code-review and security-review agents on new code; commit only when asked.
