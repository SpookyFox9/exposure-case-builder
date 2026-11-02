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
| Case unit (risk layer) | **Hybrid (decided 2026-11-02):** patch-type families (`* Local Security Checks`, `Windows : Microsoft Bulletins`) are ONE case per family; every other plugin, CISCO included (user decision), is one case per `plugin.id` | Plain per-plugin clustering gave 7,148 cases whose top 20 were near-duplicate Windows KB plugins. Hybrid gives 815 cases (15 families + 800 plugins) |
| Fix packages (engineer layer) | **Decided 2026-11-02:** a second, downstream view organized around the fix: key = normalized product (CPE) + fix type, falling back to the plugin. Each finding is in exactly one case and exactly one fix package; each links to the other | The security team needs risk-centred cases; the people who fix things need "what do I do and what does it clear". Cisco advisories roll up by product here (IOS, NX-OS) |
| Known gap | Near-duplicate plugin cases remain (e.g. Oracle Java April/July/January CPU on the same 2 hosts; two Flash advisories on one host) | A product-level rollup is a possible later step; not in v0.1 |
| Score | Transparent weighted sum, breakdown shown, weights in one table. User approved the weights 2026-11-02; KEV/VPR to be folded into the exploit component without changing weights | Explainable, no ML |
| Context fields | VPR, EPSS, CISA KEV, `solution`, `see_also`, CVEs, CPE come from the export itself | 93-99% coverage; no extra fetch needed |
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
- Record keys: `finding_id`, `state`, `severity`, `first_found`, `last_found`, `asset{uuid,hostname,ipv4,operating_system,device_type,...}`, `plugin{id,name,family,synopsis,description,exploit_available,exploited_by_malware,in_the_news,has_patch,unsupported_by_vendor,checks_for_default_account,exploit_framework_*,xrefs,cpe,...}`, `port{port,protocol,service}`, `scan{uuid,started_at,schedule_uuid,target}`, `output`, `source`. **Correction (2026-11-02):** an earlier version of this plan said the export has no `vpr`, `cvss` or `solution`. That was wrong: Tenable omits empty fields per record, so one record's keys misled. Across all 19,437 records the plugin object also has `solution`, `see_also`, `cve`, `vpr` (object with `on_cisa_kev`, `exploit_code_maturity`, drivers), `epss_score`, `cvss*`, `ms_bulletin`, `usn`, `patch_publication_date`, `vendor_unpatched`, `has_workaround`; finding records have `last_fixed`, `resurfaced_date`, `time_taken_to_fix` (only 196 findings). Coverage over 7,173 non-info plugins: solution 99%, see_also 99%, cpe 99%, vpr 93%, epss 93%, cve 93%, cvss3 89%. 3,754 distinct solution texts; "Update the affected packages." alone is on 1,781 plugins, so solution text cannot be the grouping key by itself.
- **The workbench plugin list is capped at exactly 5,000 rows**, so 3,000 of the 7,677 clusters with non-fixed findings have no workbench row. That cap affects only `plugins.json` (used for reconciliation). VPR, EPSS and CISA KEV come from the export itself at 93% coverage, so they can feed the score (see "Scoring").
- **Reconciliation** (non-fixed findings per plugin vs workbench `count`): of 4,677 comparable plugins, 4,622 match distinct hosts and 14 more match finding instances (one finding per host and port), so 4,636 (99.1%) match. The other 41 all have the export below the workbench count. The workbench saw 164 assets with vulns, the export has 160; the cause is unverified. Reconciliation is a reported tolerance (`reconcile.py`), not a hard assertion.
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
│   ├── cluster.py                  hybrid case grouping (patch families + plugins)
│   ├── scoring.py                  weighted components, breakdown, ranking
│   ├── timeline.py                 per-case timeline from first/last found dates
│   ├── reconcile.py                trust check against Tenable's plugin counts
│   ├── fixes.py                    fix packages: product + fix type, impact, links to cases
│   ├── case.py                     case assembly (Phase 4)
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

## Scoring (implemented in `scoring.py`; weights are the single source of truth)

Total = sum of component points (max 100). Every case returns the component breakdown. VPR/CVSS are not inputs (partial coverage).

| Component | Weight | Raw value (0..1) |
|---|---|---|
| severity | 30 | worst active severity: critical 1.0, high 0.75, medium 0.4, low 0.1 |
| exploit | 25 | exploited by malware 1.0, else exploit available 0.6, else 0; +0.2 if in the news (cap 1) |
| breadth | 15 | log1p(hosts) / log1p(fleet hosts) |
| volume | 10 | log1p(distinct plugins) / log1p(1000) |
| age | 5 | days since the oldest active `first_found` / 180 (cap 1) |
| unsupported | 5 | any finding on vendor-unsupported software |
| recurrence | 5 | reopened findings / 5 (cap 1) |
| patch | 5 | any finding with a vendor patch available |

Ages are measured from the latest `last_found` in the data, never the wall clock, so ranking is deterministic. Ties break on cluster id.

**Hand-check, full export (2026-11-02, after KEV/VPR; superseded detail below):** 815 cases rank in under a second. Top: Windows Microsoft Bulletins (14 hosts, 621 vulns, 86.9), Ubuntu (12 hosts, 81.8), Junos, Solaris, Oracle Linux, Red Hat; among plugin cases Shellshock (#13), then old Flash, BlueKeep, SIGRed, libcurl, Sudo, Log4j. Patch families take 14 of the top 30 because "any critical, any malware-exploited" saturates for hundreds of plugins; order among them rests on breadth, volume and age. **Weights approved by the user.**

**After KEV/VPR:** 549 of 7,148 plugins (793 findings) are on the CISA KEV list and 504 more have VPR >= 9, so every large patch family saturates the exploit component. Top cases: Windows Bulletins 86.9, Ubuntu 81.8, Junos, Solaris, Oracle Linux, Red Hat ... (14 of the top 30 are patch families); KEV pulls Cisco IOS/NX-OS RCE advisories (#15-19), old Flash (#20, #22) and BlueKeep (#21) into the top 25. Top fix packages: Ubuntu (13 hosts, 111 critical, 37 KEV), .NET Framework, Windows, Debian, OpenSSH (21 hosts, 40 vulns), CentOS, Junos, Cisco IOS. Presentation decision: the case queue must show single-plugin threats and patch backlogs as two lists (`kind` filter), because backlogs otherwise bury threats such as BlueKeep.

## MCP tools

| Tool | Output |
|---|---|
| `fleet_summary` | Totals, severity distribution, state counts |
| `clusters` | Ranked list: cluster ID, plugin, score, asset count, max severity, age, one-line reason; `top_n` |
| `cluster_case` | Summary, score breakdown, affected-asset table, timeline, fleet share, sample plugin output, remediation info, evidence record IDs |
| `export_case` | Analyst case file (Markdown, CSV, JSON); file writes need `confirm=true` |
| `fix_packages` | Ranked fix packages: product, fix type, actions, hosts, impact, cases relieved |
| `fix_package` | One package in full: actions with vulns cleared, host table, advisory links, CVEs |
| `export_fix_package` | Engineer handoff (Markdown, CSV, JSON); file writes need `confirm=true` |
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
1. [x] Hybrid clustering (`cluster.py`, 19 tests)
2. [x] Score components, ranking, documented weights (`scoring.py`, 22 tests); hand-checked on the full export
3. [x] Per-case timeline (`timeline.py`) and reconciliation report (`reconcile.py`), 9 tests
4. [x] User sign-off on the weights (2026-11-02); CISCO split from patch families

**Phase 3b: fix view (decided 2026-11-02)**
1. [x] Split CISCO from patch families; correct the PLAN facts about `solution`/VPR
2. [x] Ingest carries solution, see_also, CVEs, CPE, VPR (score, severity, KEV, exploit maturity), EPSS, CVSS3, patch date, fix dates; malformed optional fields degrade to defaults (`test_ingest_fix_fields.py`)
3. [x] `fixes.py`: 200 fix packages on the full export (125 patch, 75 configuration; 58 plugin-level fallbacks), built in 0.9 s; every one of the 10,283 active non-info findings is in exactly one package
4. [x] `links.py`: case-to-fix and fix-to-case links with shares; raises if the two views do not describe the same findings. `rank_packages` scores packages with the same approved weights
5. [x] CISA KEV and VPR folded into the exploit component, weights unchanged: KEV 1.0, malware 1.0, VPR >= 9 0.9, VPR 7-8.9 0.7, public exploit 0.6, +0.2 in the news (cap 1)
6. [x] Real `last_fixed` / `resurfaced_date` in the timeline (kinds `fixed`, `reopened`; `last_seen_*` only as fallback). On the full export every fixed or reopened non-info finding has them

Review of the fix view (python-reviewer, 2026-11-02) fixed: overflow on huge JSON integers in optional numeric fields, size caps on untrusted text and lists (4,096 chars, 100 items), package ids that could collide after slugging (now a short hash only on collision), exploit-reason ties resolved by text, a finding appearing in two cases now rejected, host details taken from the latest finding, classifier gaps ("Patch ...", "Updates ...", "Apply the workaround and disable ...", "Microsoft recommends ..."), CPE escapes and NA/wildcard values. **Impact wording:** a package's `impact` is what it CONTAINS across `actions` distinct fix actions; each action carries its own `critical_findings` and `critical_share`. Example: the Windows patch package spans 59 actions and contains 1.3% of the fleet's critical findings, but its biggest single action clears 0.22%. Not acted on: first-CPE ordering (no evidence of a problem in this data) and an EPSS upper bound (values above 1 occur). 259 tests.

Fix-type rule (documented in `fixes.py`): the solution's opening verb decides. update/upgrade/apply/install/"Microsoft has released" = `patch`; "Contact the vendor ... for an update/patch" = `patch` unless it also says disable/configure/remove etc.; everything else = `configuration`; empty = `unspecified`. `has_patch` is NOT used (true for 98% of plugins) and `has_workaround` is always false in this tenant.

**Phase 4: case and export**
1. [x] `case.py`: `CaseFile` (analyst) and `PackageView` (engineer), deterministic, JSON-ready
2. [x] `export.py`: Markdown, CSV, JSON for both views; `write_*_export` needs `confirm=true`, never leaves the output directory; golden-file tests
3. [x] Untrusted-text handling: CSV formula neutralization, Markdown/HTML escaping (backslash escapes so raw text stays readable), size caps with pointers to the complete JSON/CSV
4. [x] Security review of the exporters (python-reviewer, 2026-11-02) fixed: backslash-defeats-escape bypass (backslashes are now escaped first), link and image injection (`[ ]` escaped, advisory URLs rendered as code spans), bidi/zero-width/line-separator characters stripped, CSV leading-whitespace formula bypass, UTF-8 BOM on CSV, hash-suffixed bounded file names (collision, Windows reserved names, long names), atomic writes via temp file and `os.replace` (replaces a symlink rather than following it), floored percentages (never 100% unless exact), clearer headers ("address", "alone clears"), timeline cap keeps the most recent events, singular "1 day", tz-aware `as_of` required, unknown severities rejected at ingest. Not acted on: Slack/Jira escaping (Markdown is the documented target; JSON is the exact copy). 345 tests (1 skipped where Windows cannot create symlinks).
5. [x] Real-data check: all 200 packages and 815 cases render in 0.5 s; largest Markdown 12 KB, largest JSON 876 KB; no formula-capable CSV cells and no raw angle brackets

**Phase 5: MCP, skill, playbook**
1. [x] `disposition.py`: append-only JSONL, fixed vocabulary, `confirm=true`, validated and bounded fields, latest-wins read (30 tests)
2. [x] `service.py`: `Workspace` answers every tool question as capped JSON; ids validated against the loaded data; no tool takes a path (35 tests on the committed sample)
3. [x] `server.py`: 8 tools over stdio (`fleet_summary`, `case_queue`, `fix_queue`, `case_file`, `fix_package`, `findings`, `export`, `record_disposition`); queue returns threats and backlogs as two lists; anticipated errors surface their message via `ToolError`, bugs stay opaque; 17 contract tests drive the real server with the SDK client (annotations, confirm gates, error messages, startup failures)
4. [x] `skills/exposure-case/SKILL.md` and `playbooks/exposure-case-playbook.md`; `tests/test_skill.py` fails if a tool is undocumented or the skill names one that does not exist
5. [ ] Register the server with Claude Code and run one live session (user runs `claude mcp add`; see the playbook)
6. [x] Review pass (python-reviewer) on `service.py`, `server.py`, `disposition.py`, 2026-11-02. Fixed: `confirm`/`write` are strict booleans (the SDK refuses "true", 1, "yes"); the docs and error text no longer claim the server verifies human approval (it cannot; Claude Code's tool-permission prompt is the real gate, so keep both write tools on "ask"); server instructions and the skill say Tenable text and recorded notes are data, never instructions; a corrupt or hostile disposition-log line is skipped and counted (`log_warnings`) instead of breaking every queue call; log entries are type-checked, reads are cached by mtime/size, and the log is capped at 5 MB; case files and packages are built once per id; inline exports are capped at 60,000 characters with a pointer to `write=true`; vulnerability solution text is shortened to 500 characters in tool output and `max_vulns` is capped at 100; exports report file names only (no absolute paths); `kind`, `format` and `disposition` are enums in the tool schema. Not acted on: retracting a disposition (append a new entry instead), an OS-level file lock for two server instances (single small appends), and MCP elicitation (client support unverified).
7. [x] Tenable User-Agent: every API call sends `Integration/1.0 (VENDOR; PRODUCT; Build/VERSION)` per https://developer.tenable.com/docs/user-agent-header (read 2026-11-02; Tenable "recommends" it and lists it as a validation criterion in the VM integration guide). The page does not mention contact details in the string; vendor defaults to the project name and `TENABLE_UA_VENDOR` overrides it. 8 tests. The survey scripts used earlier in this session (scratchpad, outside the repo) sent Python's default agent.

**Phase 6: polish and submit**
1. [x] Full-history secret scan: 12 commits, gitleaks clean; commits use the GitHub noreply address; no personal email in history. The Windows username appears in a path in two early commits (not rewritten; removed from the current tree)
2. [x] README finished: every Exchange-required section, a data-flow section naming every outbound call, honest limitations, security notes, dependency licenses. Install verified from a fresh clone: `uv sync`, 472 tests, server answers on the sample
3. [x] Exchange listing drafted at `docs/exchange/mcp-server-listing.md` (MCP server, validated by `tests/test_listing.py` against the vocabularies read on 2026-11-02 and against the real server's tool list)
4. [ ] One live Claude Code session on the sample (user runs `claude mcp add`; see the playbook)
5. [ ] Create the public GitHub repo on the personal account and push (user)
6. [ ] Tag v0.1.0 after the live session and push the tag
7. [ ] Fork tenable/cyberagents-exchange, copy the listing to `mcp-servers/exposure-case-builder.md`, set `contribution_agreement_date` to the moment you accept the CyberAgents Contribution Agreement, set the final `github_url` and `date_added`, run the Exchange's own `uv run ./validator.py`, open the PR titled `Add listing: Exposure Case Builder` with the acceptance statement in the description
8. [ ] Decide on a second listing for the skill (the checklist as reported wants `SKILL.md` at the repo root; ours is in `skills/exposure-case/`) and rehearse the demo; confirm submission details at office hours

## Risks

- **High:** the score reads as arbitrary. Mitigation: breakdown, one weights table.
- **Resolved:** full export size and time (30 s, 108 MB, loads in 0.6 s).
- **High:** 7,148 clusters, so ranking quality is the product. Mitigation: documented components, hand-checked top 20 against the data.
- **Medium:** Tenable already ranks by VPR. Lead the demo with clustering, evidence, handoff export and disposition.
- **Medium:** remediation text may need another endpoint (another outbound call).
- **Medium:** time; the target is a working demo by the end of Tuesday.
- **Low:** masked identifiers; treated as opaque.

## Unverified items (do not assume)

- Official Rules were not read. Open: whether pre-existing code is allowed or work must start during the event; repo-structure, demo-video and pitch-deck requirements; data restrictions; whether all submissions or only winners must be listed on the Exchange. This repo was started before the event (Nov 2 evening); the pivot to Tenable data happened during it.
- Submission deadline and pitch-selection process; assumed Wednesday Nov 4, confirm at office hours.
- Exchange mechanics, **verified 2026-11-02 from tenable/cyberagents-exchange (README, CONTRIBUTING.md, validator.py, templates, docs/contributing_checklist.md)**: one new markdown file per PR (so one PR per listing); branch `add-<slug>`; PR title `Add listing: <Name>`; PR description must state acceptance of the CyberAgents Contribution Agreement; `tier` must be `contributed`; `domains` and `contribution_agreement_date` are required in practice; `github_url` and `author` must match the real remote; no release-tag field. Not read: the Contribution Agreement itself, SECURITY.md, the submission-builder skill. The skill that automates this (`/cyberagents-exchange-submit`) is not installed in this environment.
- Tenable's User-Agent guide says "recommends"; the VM integration guide lists it as a validation criterion.
- Judging criteria and weights are unpublished. The user's priority is impact on real security work.
- Tenable items listed under "Tenable data facts".

## Status (update as work lands)

Last updated: 2026-11-02, Monday evening.

- Done: pivot decided and confirmed (finding-cluster cases, reuse repo, tenant data is fake and usable, live fetch allowed as a documented path).
- Done: Tenable keys stored in `~/.secrets/tenable.cred.xml` (DPAPI); `tenable-env.ps1` loads them per session. Survey scripts live in the session scratchpad, not the repo.
- Done (Phase 1): package renamed to `exposure_case`; insider generator, data and tests removed; `Finding` now uses `subject`; 8 tests pass; docs rewritten. Nothing is committed yet.
- Done (Phase 2): `ingest.py`, `scripts/fetch_tenable.py`, `scripts/make_sample.py`, `data/sample/` (1.3 MB, gitleaks clean). 139 tests pass. The full export lives in `data/raw/full1` (gitignored, about 108 MB). Committed as `094e311`.
- Done (Phase 3b): ingest fix fields, `fixes.py`, `links.py`, KEV/VPR in scoring, real fix dates in the timeline; 259 tests, ruff and mypy clean.
- Done (Phase 3): `cluster.py`, `scoring.py`, `timeline.py`, `reconcile.py`; 139 tests pass; ruff and mypy clean. 815 cases from the full export (15 patch families, 800 plugins). Weights approved.
- Done (Phase 4): case file and package view with Markdown/CSV/JSON exports, security-reviewed; 345 tests, ruff and mypy clean.
- Done (Phase 5, pending review): disposition log, service layer, 8-tool MCP server with contract tests, skill and playbook; 472 tests, reviewed.
- Done (Phase 6, local part): history scan, README, fresh-clone install check, drafted Exchange listing. 481 tests.
- Next, all needing the user: the live Claude Code session, creating the public GitHub repo, tagging v0.1.0, and the Exchange PR (it carries the user's own acceptance of the Contribution Agreement).

## Resuming in a new session

```bash
cd <path to this repo>
uv sync                      # create .venv with pinned deps (Python >=3.10)
uv run pytest                # run tests
```

- Read `CLAUDE.md`, then this file's Status and Build order. Continue at the first unchecked item.
- To use the Tenable API in PowerShell: `. $HOME\.secrets\tenable-env.ps1` (loads env vars for that session). To re-store keys, run `powershell -File $HOME\.secrets\tenable-store.ps1` in a real terminal, not through `!`.
- gitleaks is installed via winget (`Gitleaks.Gitleaks`). The hook runs `gitleaks git --staged`. `gitleaks dir .` reports false positives inside the gitignored `.venv`; scan the staged diff or history instead.
- The research doc lives outside the repo, in the parent folder. Keep it out. Read only section 3 (Exchange contribution process).
- Workflow reminders: write tests first; run the code-review and security-review agents on new code; commit only when asked.
