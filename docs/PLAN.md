# Insider Case Builder: Build Plan

Living plan for the SWARM Global build (Nov 2–6, 2026). Update the **Status** section as work lands. A new session should read this file and `CLAUDE.md` first.

## What we're building

Insider Threat Case Builder baselines each user's activity against their peers, uses rule-based detectors to flag deviations such as off-hours logons, first-time USB use, file-copy spikes and job-site browsing, and assembles a case file with a timeline and the source records behind every finding. Claude then writes the case narrative and suggests next investigative steps, and the human analyst records the final disposition.

Three components with a fixed division of labor:

1. **Deterministic Python engine** (stdlib only). Ingests CSV, builds per-user and peer-group baselines, runs detectors, assembles case files. No ML.
2. **Stdio MCP server** wrapping the engine.
3. **Claude Code skill** (`/insider-case`) plus a short playbook that chains the tools.

## Decisions made

| Decision | Choice | Why |
|---|---|---|
| Input format | CSV only (no Parquet) | CERT is CSV; Parquet needs `pyarrow`, against the stdlib-first rule |
| Disposition | Fifth MCP tool `record_disposition`: local append-only JSONL, requires `confirm=true`, no external effect | Brief requires a recorded human disposition; Exchange guidance asks for explicit confirmation on writes. Document as the only write in the README |
| MCP SDK | `mcp==2.3.0` (fallback `1.30.0`) | See "MCP SDK facts" below |
| Test data order | Synthetic generator first, CERT second | Never blocked on the download |
| Repo location | `insider-case-builder/` subdirectory of the SWARM vault folder | Keeps the research doc and `.obsidian` out of the public repo |
| Python | >=3.10 via `uv` (default `python` here is 3.9.13, too old) | `mcp` requires >=3.10 |

## MCP SDK facts (checked 2026-11-02)

- `mcp` 2.3.0 on PyPI (released 2026-10-02) requires Python >=3.10. 2.x began 2026-07-28; previous line is 1.30.0.
- Bundled `mcp-types` knows protocol revisions 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25 (handshake) and 2026-07-28 (modern stateless).
- 2.x removed `FastMCP`. Use `from mcp.server.mcpserver import MCPServer`.
- SDK client and server negotiated **2025-11-25** over stdio in our smoke test.
- **Not yet verified:** that Claude Code's own MCP client connects to the 2.3.0 server. See "Next steps".

## Constraints (from the brief)

- MIT license; public repo on a personal GitHub account (not EMU).
- No secrets anywhere in git history (automatic Exchange rejection even if rotated). The pre-commit gitleaks hook stays on.
- Synthetic or public data only. Never reference any employer or any real organization's data, policies, field names or detection content.
- Never commit raw CERT files. Ship a download script and a small synthetic sample.
- Read-only by default; no outbound network calls unless documented in the README; output is evidence and facts, not verdicts; no HR or disciplinary recommendations.
- Pin every dependency; justify each third-party one. The engine is stdlib-only, and `mcp` is the single runtime dependency.
- Every finding carries the source records that triggered it.

## Repo layout

```
insider-case-builder/
├── LICENSE, README.md, CLAUDE.md, pyproject.toml, uv.lock
├── .githooks/pre-commit        gitleaks on staged changes
├── src/insider_case/
│   ├── schema.py               frozen dataclasses (Event, Finding, Evidence)
│   ├── ingest/                 csv readers, normalizers
│   ├── baseline.py             per-user and peer-group stats
│   ├── detectors/              one module per detector + registry
│   ├── case.py                 timeline and case_file assembly
│   ├── disposition.py          append-only local JSONL log
│   └── server.py               MCP stdio server (thin wrapper)
├── data/synthetic/             generator output (small, committed)
├── scripts/                    make_synthetic.py, download_cert.py, subset_cert.py
├── skills/insider-case/SKILL.md
├── playbooks/insider-case-playbook.md
├── tests/
└── docs/                       PLAN.md, data-flows.md, detector-catalog.md
```

**README sections (Exchange requires):** Purpose, Prerequisites, How to run (synthetic quickstart, then CERT, then MCP config for Claude Code), Outputs, Known limitations, Data flows (state "no outbound calls"; the CERT download script is the one documented exception), Data sources and licensing. Tag a release (v0.1.0) and submit from the tag.

## Data plan

**Synthetic generator (first).** Seeded and reproducible. Emits CERT-shaped files: `logon`, `device`, `file`, `email`, `http`, a roster, and an `answers` file. About 50 users across 3–4 departments, 6 planted insiders across 3 patterns, 2 benign decoys that look odd (for example, a late-night release engineer).

**CERT r4.2.**
- `download_cert.py` fetches from the KiltHub DOI 10.1184/R1/12841247 and verifies a checksum.
- `subset_cert.py` streams each large CSV once, keeping about 50 users: about 8 insiders across the scenarios plus about 42 others from the same departments and roles. Fixed seed.
- `data/raw/` and `data/subset/` are gitignored.

**Unverified (recalled from memory, confirm on the real files):** CERT column layouts, the answers folder structure, and r4.2 containing 3 scenarios. The first job on the real download is to inspect headers and fix the schema. **License/access is unclear** (CC BY 4.0 on a mirror vs. a KiltHub registration claim). Read the KiltHub page before scripting the download. Reported r4.2 duration conflicts across sources (17 months, 18 months, 500 days).

## Detectors (rule-based, each finding cites source record IDs)

| # | Detector | Fields | Rule |
|---|---|---|---|
| D1 | Off-hours logon | logon: user, pc, date, activity | Logon outside the user's own typical hour band |
| D2 | First-seen removable media | device: user, pc, activity | First connect ever for the user, or on an unusual PC |
| D3 | File-copy spike | file: user, date, filename | Daily count above user median + k·MAD and above peers |
| D4 | Job-site browsing | http: user, url; roster end date | Job-board domain visits, weighted toward the weeks before departure |
| D5 | Exfil-site visit | http: url | Domains on a documented upload/leak-site list |
| D6 | External email with attachment | email: recipients, attachment_count, size | Non-corporate recipient plus attachment vs. user baseline |
| D7 | Unusual-PC logon | logon: user, pc | Logon on a PC that isn't the user's usual one |
| D8 (stretch) | Off-hours device use | device + logon | D1 and D2 in the same session |

**Validation.**
1. Per-insider recall (is the user flagged at all) and per-event recall (does a finding point at an answer event), using the answers files.
2. Rank all users by score; report how many insiders land in the top 5/10 and false positives per benign user.
3. Tune thresholds on about half the users and report on the other half; state the split.
4. Unit tests with hand-built fixtures for every detector (positive, negative, boundary).
5. Expect uneven results (scenario 3, the keylogger case, may be weak). The README says so plainly.

## MCP tools

All read-only except `record_disposition`. The dataset path comes from `INSIDER_CASE_DATA` or a server argument; no tool accepts arbitrary file paths.

| Tool | Input | Output |
|---|---|---|
| `baseline` | `user_id`, optional `window_days` | `{user, peer_group, stats:{logon_hours, devices, file_copy_daily, email_ext_daily, ...}, peer_stats, n_days}` |
| `anomalies` | `user_id` or `"all"`, optional `date_from`, `date_to`, `detectors[]`, `top_n` | `{findings:[{id, detector, user, date, score, rationale, evidence:[{source, record_id}]}], ranking:[{user, score}]}` |
| `timeline` | `user_id`, `date_from`, `date_to`, `sources[]` | `{events:[{ts, source, record_id, summary}]}` chronological |
| `case_file` | `user_id`, optional date range | `{user, role, period, findings, timeline, peer_comparison, facts_summary, limitations, disposition:null}` |
| `record_disposition` | `case_id`, `analyst`, `disposition`, `note`, `confirm` | `{recorded, path, entry}`; rejects unless `confirm=true` |

## SKILL.md outline (`/insider-case`)

1. When to use it, and the facts-not-verdicts boundary, with an explicit ban on HR or disciplinary recommendations.
2. Workflow: `anomalies(all)` for triage, `baseline` per candidate, `timeline` around top findings, `case_file`, then the narrative.
3. Narrative rules: every claim cites a record ID, uncertainty is stated, benign explanations are listed beside concerning ones.
4. Next investigative steps stay on evidence (what else to pull), never on action against the person.
5. Hand-off: the analyst states a disposition; only then call `record_disposition`.
6. Failure handling for missing data or empty tool results.

## Testing strategy

- **Unit tests per detector (pytest, written first).** Hand-built fixtures; every finding asserts non-empty source record IDs.
- **Synthetic end-to-end tests.** The generator plants known insiders and decoys, so recall and precision are exact. Also test generator determinism and schema.
- **MCP contract tests.** An SDK client spawns the stdio server, calls each tool, checks output schemas and clean failure on bad input.
- **CERT validation (Wed).** Real answer files, with tuning on a held-out split.
- **Security gate.** gitleaks on every commit; a full-history scan before the Exchange PR.
- **Demo check.** A case narrative may cite only record IDs that exist in the data.
- Caveat: synthetic data tests the code, not real-world detection quality.

## Build order

**Mon Nov 2 evening**
1. [x] Repo, MIT license, `.gitignore`, `.gitattributes`, gitleaks pre-commit hook
2. [x] `mcp==2.3.0` stdio smoke test, SDK client only
3. [ ] Smoke test from Claude Code itself. `insider-smoke` is registered (user ran `claude mcp add`); still need to reload MCP, confirm in `/mcp`, and call `ping`
4. [x] Schema dataclasses and synthetic generator (test-first)
5. [x] README skeleton
6. [ ] Start the CERT download in the background, only after the license check

**Tue Nov 3 (end-to-end demo by end of day)**
1. Morning: ingest, baselines, D1, D2, D3, D5, with tests
2. Midday: `case_file` and `timeline`. Checkpoint: a CLI-driven case for a planted synthetic insider
3. Afternoon: MCP server with all tools; D4, D6, D7
4. Evening: SKILL.md v1 and the playbook. Demo runs on synthetic data: Claude Code calls the tools, writes a cited narrative, the analyst records a disposition

**Wed Nov 4 onward (polish)**
- Subset real CERT; measure recall and precision on the held-out split
- Add a false-positive case file; polish the disposition log
- Full-history secret scan, tag v0.1.0, open the Exchange PR (use the `/cyberagents-exchange-submit` skill)
- Attend Wednesday office hours (see open questions); prepare the 15-minute pitch built around one live case walk-through

## Risks

- **High:** CERT download size, license and access terms. Mitigation: synthetic-first, so the demo never depends on it.
- **High:** Scope creep into ML. Mitigation: detectors stay rule-based.
- **Medium:** The "surveil a third party" Exchange hard line and PII sensitivity. Mitigation: defensive framing, synthetic data, read-only, every data flow documented.
- **Medium:** Claude Code may not connect to `mcp` 2.3.0. Mitigation: smoke test now; fall back to 1.30.0.
- **Medium:** Detectors may be weak on some CERT scenarios. Mitigation: report honestly.

## Unverified items (do not assume)

- Official Rules were not read. Open: whether pre-existing code is allowed or work must start during the event; repo-structure, demo-video and pitch-deck requirements; data restrictions; whether all submissions or only winners must be listed on the Exchange.
- Submission deadline and pitch-selection process. This plan assumes submission on Wednesday; confirm at office hours.
- Whether a duplicate registration on the SWARM page is harmless.
- The Exchange repo details (`/cyberagents-exchange-submit`, `validator.py` vocabularies) came from the research doc; they were not re-fetched.
- CERT license, date range, and column and answers layouts (see Data plan).
- Judging criteria and weights are unpublished. At Black Hat, judges "scored impact above everything else", and winners were deterministic, evidence-attached, read-only and human-decided, with synthetic data.

## Status (update as work lands)

Last updated: 2026-11-02, Monday evening.

- Done: repo scaffold, MIT license, gitleaks pre-commit hook (ran clean on the first commit); `mcp==2.3.0` SDK-to-SDK stdio smoke test; pins checked against PyPI (`pytest==9.2.0`, `hatchling==1.33.0`).
- Done: `schema.py` (frozen `Evidence`, `Event`, `Finding`; a Finding needs non-empty evidence and a finite score) and the seeded synthetic generator (`synthetic.py`, `scripts/make_synthetic.py`). 50 users, 6 planted insiders across 3 scenarios (`job_site_exfil`, `usb_file_copy`, `email_exfil`), 2 decoys. The answer key is in `data/synthetic/_labels/answers.csv`, kept apart from the source files; ingest must never read `_labels/`.
- Done: README skeleton with the Exchange-required sections (several marked TODO). 18 tests pass. python-reviewer found no CRITICAL or HIGH issues; MEDIUM fixes applied.
- Committed: `d02777b` on `main` (not pushed). `scripts/mcp_smoke.py` is deliberately untracked until the smoke test is done.
- In progress: Claude Code smoke test. `insider-smoke` is registered in local config. Next: reload MCP or restart and `/resume`, check `/mcp`, ask Claude to call `ping`. On success, delete `scripts/mcp_smoke.py` and run `claude mcp remove insider-smoke`; on failure, pin `mcp==1.30.0`.
- Not started: CERT license check and download (step 6), detectors, baselines, case assembly, MCP server, skill, playbook, README body.
- Deferred review items: split `generate()` and group `_baseline_day` parameters into a config object; add a golden-hash determinism test; consider trimming the 2.5 MB committed sample.
- Generator facts for detector tests: timestamps are ISO (`YYYY-MM-DD HH:MM:SS`), not CERT's `MM/DD/YYYY`, so the real-CERT normalizer is still to write. Insider activity falls in the last 20 workdays. Benign decoys: `U0001` (late-night release engineer), `U0003` (frequent external attachments). Two benign non-insiders also have a roster `end_date`.

## Resuming in a new session

```bash
cd "C:/Users/maupi/Documents/Obsidian Vault/SWARM/insider-case-builder"
uv sync                      # create .venv with pinned deps (Python >=3.10)
uv run pytest                # run tests
uv run pytest tests/test_x.py::test_name   # single test
```

- Read `CLAUDE.md`, then this file's Status and Build order. Continue at the first unchecked item.
- gitleaks is installed via winget (`Gitleaks.Gitleaks`). Shells opened before the install need a restart to see it on PATH. The hook runs `gitleaks git --staged`.
- `gitleaks dir .` reports 7 false positives inside the gitignored `.venv` (third-party crypto libraries). Ignore them; scan the staged diff or `git` history instead.
- Claude Code smoke test (run in a prompt, since it edits Claude config), then ask Claude to call `ping`:
  ```
  ! claude mcp add insider-smoke -- uv run --directory "C:/Users/maupi/Documents/Obsidian Vault/SWARM/insider-case-builder" python scripts/mcp_smoke.py
  ```
  If it connects, keep 2.3.0 and delete `scripts/mcp_smoke.py` and the registration (`claude mcp remove insider-smoke`). If it fails, switch the pin to `mcp==1.30.0`.
- The research doc lives outside the repo, in the parent folder (`SWARM Global 2026_ Entry Status, Rules, and a Solo Build Plan for a Security Analyst.md`). It is not part of the public repo; keep it out. Read only what a task needs: section 3 (Exchange contribution process) and section 7, Idea 1. It is about 50 KB.
- Workflow reminders: write tests first; run the code-review and security-review agents on new code; commit only when asked.
