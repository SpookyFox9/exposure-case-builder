# Exposure Case Builder: Build Plan

Living plan for the SWARM Global build (Nov 2-6, 2026). A new session should read this file and `CLAUDE.md` first. Design is in `docs/architecture.md`; the rules audit is in `docs/ENGINEERING_AUDIT.md`; prior art is in `docs/PRIOR_ART.md`.

**Pivot (2026-11-02):** the project began as an insider-threat case builder on CERT data. The competition Tenable tenant has no user-activity telemetry (only users, assets, scans, vulnerability findings), so the build targets vulnerability exposure. The insider code is in git history (`56f8788` and earlier).

## What we're building

An MCP server and Claude Code skill that turn a Tenable Vulnerability Management export into two linked views of the same findings: **cases** for the security team (what is risky, ranked, with evidence) and **fix packages** for the people who fix things (what to do, what it clears, on which hosts). Claude writes the cited narrative; the human analyst records the decision. A deterministic stdlib engine does all clustering, scoring and evidence collection. No ML.

## Decisions made

| Decision | Choice | Why |
|---|---|---|
| Domain | Vulnerability exposure, not insider threat | The tenant data fits; the user judged insider threat added needless complication. Prior art in this domain exists (see `PRIOR_ART.md`); we are differentiated, not novel |
| Case unit (risk layer) | Patch-type families (`* Local Security Checks`, `Windows : Microsoft Bulletins`) are one case per family; every other plugin, CISCO included (user decision), is one case per `plugin.id` | Plain per-plugin clustering gave 7,148 cases whose top 20 were near-duplicate KB plugins. Hybrid gives 815 (15 + 800) |
| Fix packages (engineer layer) | Key = normalized product (CPE vendor:product) + fix type (from the solution's opening verb), falling back to the plugin. Every active finding is in exactly one case and one package; each links to the other | Security wants risk-centred cases; fixers want "what do I do and what does it clear" |
| Score | One transparent weighted sum with a component breakdown; weights approved by the user 2026-11-02; KEV and VPR feed the exploit component without changing weights | Explainable, no ML |
| Two-list queue | `case_queue` returns single-vulnerability *threats* and patch *backlogs* separately | KEV is common here, so large backlogs saturate the exploit component and would bury threats such as BlueKeep |
| Impact wording | A package's totals are what it *contains* across several distinct actions; only each action's own row says what it alone clears | Tenable's data does not say one update supersedes another |
| Disposition | `assigned`, `risk-accepted`, `false-positive`, `needs-info`; append-only local JSONL, latest per item wins, `confirm=true`; bulk views omit the free-text note | Human decides; a stored note is replayed to a model |
| Fetch client | stdlib `urllib`, not pyTenable | pyTenable needs Python >= 3.11 and 14 runtime dependencies for a four-endpoint fetch; see `PRIOR_ART.md` |
| Rules | The user's `common/` and `python/` rules are copied into `.claude/rules/` (gitignored: private instructions, licence unknown); the enforceable parts are committed tooling | See `CLAUDE.md` and `ENGINEERING_AUDIT.md` |
| Data | Competition tenant (fake, masked); trimmed sample committed (no plugin output); full export gitignored | The user confirmed it is all fake data |
| Secrets | DPAPI-encrypted `~/.secrets/tenable.cred.xml`, loaded to env vars per session; `TENABLE_UA_VENDOR=SpookyFox9` is set there | Nothing in the repo |
| Output locations | Absolute; default `~/.exposure-case/` | Never relative to the working directory |
| MCP SDK / Python | `mcp==2.3.0`; Python >= 3.10, tested on 3.10 and 3.14 | `from mcp.server.mcpserver import MCPServer` |
| Submission | One MCP-server listing (`docs/exchange/mcp-server-listing.md`) | The rules allow one submission per team and one file per PR |

## Tenable data facts (surveyed 2026-11-02, cloud.tenable.com)

- Full export (fetched in 30 s, about 108 MB): **19,437 findings, 160 hosts, 7,714 plugins, 18 scans** (7,148 plugins with active non-info findings). States: 18,448 OPEN, 604 REOPENED, 385 FIXED. 10,283 active non-info findings, 793 of them on CISA KEV. `num_assets` is the assets per chunk, not a limit.
- The export's plugin object carries `solution` (99% of plugins), `see_also` (99%), `cpe` (99%), `vpr` with `on_cisa_kev` (93%), `epss_score` (93%), `cve` (93%), `cvss3` (89%). Tenable omits empty fields per record, so one record's keys can mislead (an early version of this plan wrongly said `solution` was absent). Finding records carry `last_fixed`, `resurfaced_date`, `time_taken_to_fix` for a small minority (unit: seconds).
- 3,754 distinct solution texts; "Update the affected packages." is on 1,781 plugins, so solution text cannot be the grouping key alone.
- The workbench plugin list is capped at 5,000 rows; it is used only for reconciliation. Of 4,677 comparable plugins, 4,636 (99.1%) match Tenable's count as distinct hosts or finding instances; 41 do not, all with the export lower (cause unverified; the workbench saw 164 assets, the export has 160).
- No tags; two groups; 75 users; the audit log returns HTTP 403 for the key used. Hostnames and IPs are masked: never research them.

## Repo layout

```
insider-case-builder/               (directory name is a leftover; package is exposure_case)
├── LICENSE (MIT), README.md, CLAUDE.md, pyproject.toml, uv.lock
├── .githooks/pre-commit            gitleaks, then scripts/check_all.sh
├── .github/workflows/ci.yml        scripts/check_all.sh on Python 3.10 and 3.12; actions pinned to commits
├── .claude/rules/                  private copy of the user's rules (gitignored)
├── src/exposure_case/
│   ├── common.py, text_safety.py, schema.py        shared pieces and the Evidence type
│   ├── ingest.py                                    saved export -> FindingRecord
│   ├── cluster.py, fixes.py, links.py               cases, fix packages, the links between them
│   ├── scoring.py, timeline.py, reconcile.py        ranking, dated events, trust check
│   ├── case.py, report_md.py, export.py             case file / package view, Markdown, CSV+JSON+writers
│   ├── disposition.py                               append-only decision log
│   └── service.py, server.py                        Workspace (tool answers) and the stdio MCP server
├── scripts/                        fetch_tenable.py (the one outbound path), make_sample.py, check_standards.py, check_all.sh
├── data/sample/                    1,125 findings, 154 hosts, 50 plugins (fake, masked, no plugin output)
├── skills/exposure-case/SKILL.md, playbooks/exposure-case-playbook.md
├── tests/                          unit, integration and e2e (conftest assigns the markers)
└── docs/                           PLAN.md, architecture.md, ENGINEERING_AUDIT.md, PRIOR_ART.md, exchange/
```

## Scoring (`scoring.py` is authoritative)

Total = sum of component points (max 100); every case and package returns the breakdown.

| Component | Weight | Raw value (0..1) |
|---|---|---|
| severity | 30 | worst active severity: critical 1.0, high 0.75, medium 0.4, low 0.1 |
| exploit | 25 | strongest signal on any finding: CISA KEV 1.0, exploited by malware 1.0, VPR >= 9 0.9, VPR 7-8.9 0.7, public exploit 0.6; +0.2 if in the news (cap 1) |
| breadth | 15 | log1p(hosts) / log1p(fleet hosts) |
| volume | 10 | log1p(distinct plugins) / log1p(1000) |
| age | 5 | days since the oldest active `first_found` / 180 (cap 1) |
| unsupported | 5 | any finding on vendor-unsupported software |
| recurrence | 5 | reopened findings / 5 (cap 1) |
| patch | 5 | any finding with a vendor patch available |

Ages are measured from the newest `last_found` in the data, never the wall clock; ties break on id. On the full export 549 of 7,148 plugins are on KEV and 504 more have VPR >= 9, so 14 of the top 30 cases are patch families; the two-list queue exists for that reason. Top cases: Windows Microsoft Bulletins 86.9, Ubuntu 81.8, Junos, Solaris, Oracle Linux, Red Hat; among threats Shellshock, old Flash, BlueKeep, SIGRed, libcurl, Sudo, Log4j.

## MCP tools (`server.py` is authoritative; `tests/test_skill.py` and `tests/test_listing.py` enforce it)

| Tool | Writes? | Purpose |
|---|---|---|
| `fleet_summary` | no | Totals, severity, case and package counts, KEV, data-quality notes |
| `case_queue` | no | Ranked cases as `threats` and `backlogs` (or one kind); `hide_dispositioned` reports how many it hid |
| `fix_queue` | no | Ranked fix packages |
| `case_file` | no | One case: score breakdown, facts, linked packages, vulnerabilities, hosts, timeline, limitations, disposition |
| `fix_package` | no | One package: Tenable's actions with what each clears, contained impact, hosts, CVEs, advisories, cases |
| `findings` | no | Real finding records behind a case or package, paged, so a narrative cites genuine ids |
| `export` | with `write=true` and `confirm=true` | Markdown / CSV inline (size-capped); all formats to the export directory |
| `record_disposition` | yes, `confirm=true` | One appended line in the decision log |

No tool accepts a file path. `confirm` is a convention: the client's tool-permission prompt is the real gate.

## Testing strategy

Unit tests per module (test first, RED observed), the MCP contract tests (real server, real SDK client), an end-to-end flow (fake Tenable -> fetch script -> server -> export -> decision), golden-file tests for the exporters, drift guards (skill, listing, workflow gates), and the standards checker run over this repo. Coverage gate 80% (actual 96% branch). A hash of every export and tool answer on the full real tenant (1,015 items) and on the sample (93) is used to prove behavior-neutral refactors.

## Build status

| Phase | What | Status |
|---|---|---|
| 1-2 | Reset to the new domain; ingest; fetch script; sample | done (`a186308` and earlier) |
| 3, 3b | Clustering, scoring, timeline, reconciliation; fix packages, links, KEV/VPR, real fix dates | done |
| 4 | Case files and Markdown/CSV/JSON exports, security-reviewed | done |
| 5 | Disposition log, service, 8-tool MCP server, skill, playbook | done, reviewed twice |
| 6 (local) | History scan, README, fresh-clone install check, Exchange listing draft | done |
| Audit | Rules audit, whole-repo security and code review, prior-art research, standards checker, hook, CI | done 2026-11-02 (`docs/ENGINEERING_AUDIT.md`) |
| Submit | Live Claude Code session; public repo; tag v0.1.0; Exchange PR | **open, needs the user** |

## Submission checklist (needs the user)

1. Confirm eligibility: the rules require registering at info.tenable.com/2026-SWARM-GLOBAL.html before it closed (Nov 1), joining the Discord, and every contributing member accepting the CyberAgents Contribution Agreement. Read the agreement (not fetched here): it covers licence, authority including "any required employer permission", and non-infringement.
2. Ask on Discord for the **Submission Deadline** (the rules use the term but never define it) and how to **notify Tenable** of the submission.
3. Run one live Claude Code session on `data/sample` (`claude mcp add`; see the playbook). Keep `export` and `record_disposition` on "ask".
4. Create the public repository on the personal account and push. The listing assumes `github.com/SpookyFox9/exposure-case-builder`.
5. Tag `v0.1.0`.
6. Fork `tenable/cyberagents-exchange`; copy `docs/exchange/mcp-server-listing.md` to `mcp-servers/exposure-case-builder.md`; set `contribution_agreement_date` to your own acceptance time, the final `github_url` and `date_added`; run the Exchange's own `uv run ./validator.py`; open the PR titled `Add listing: Exposure Case Builder` with the acceptance statement in the description.
7. Pitch (Thu Nov 5, selected teams, about 15 minutes) and awards (Fri Nov 6): build the demo around one live case walk-through on the sample.

## Verified facts about the competition (2026-11-02)

- Rules (exchange.tenable.com/swarm-global-rules-nov2026): teams of 1-3; one submission per team, to the CyberAgents Exchange, per its contribution guidelines; judges are a panel of Tenable (possibly Anthropic) staff choosing 1st-3rd place with **no published criteria or weights**; no demo, video or deck requirement is stated; pre-existing code and data restrictions are not addressed (this repo's first commit was 12:51 ET Nov 2, after the 11:00 ET kickoff); BYOT; MIT preferred. Prizes: $10,000 of Anthropic platform credits ($5,000 / $3,000 / $2,000), EXPOSURE 2027 passes, patches, featured Exchange placement. Contest period Nov 2 11:00 ET to the awards stream Nov 6.
- Exchange mechanics (README, CONTRIBUTING.md, `docs/contributing_checklist.md`, `validator.py`, templates): one new markdown file per PR; branch `add-<slug>`; `tier` must be `contributed`; `github_url` and `author` must match the real repo; an MCP-server listing is checked for runtime-versus-manifest, transport and tools-versus-code congruence; secrets are scanned over the full history; the README needs purpose, prerequisites, how to run, outputs and limitations.

## Risks

- **High:** the Exchange contribution agreement and employer permission are the user's to read and attest; nothing here substitutes for that.
- **Medium:** judging criteria are unpublished; the live Claude Code session has not been run, so narrative quality is untested beyond the contract tests.
- **Medium:** overlap with existing listings (Patch Shepherd, the vetted Remediation Priority & Impact Agent, the Chokepoint family); positioning must stay honest.
- **Low:** the ranking weights are a judgment, not validated against outcomes.

## Unverified (do not assume)

- The Contribution Agreement text, SECURITY.md, and the submission-builder skill's checks (only a model summary of its SKILL.md was available).
- Whether the Submission Deadline is Wed Nov 4 (assumed) or later.
- The minimum Tenable role for exports is now documented (Basic [16] + Can View on assets, per developer.tenable.com export reference); the workbench call's minimum was not checked.
- The cause of the 41 count mismatches against Tenable's own numbers.
- Whether MCP elicitation is supported by the client (not used; `confirm` plus the client prompt is the gate).
- The Chokepoint Finder repositories (only their listing files were read).

## Status

Last updated: 2026-11-02, late afternoon (HEAD `75aa694` or later). 557 tests pass at 96% branch coverage on Python 3.10 and 3.14; `sh scripts/check_all.sh` (ruff, black, mypy, bandit, standards checker, coverage gate) is clean; full-history secret scan clean. Everything buildable without the user is built; the open items are the submission checklist above.

Antivirus note: BitDefender quarantined pytest's `lastfailed` cache as `Generic.DDE.Exploit` (test ids embedded the Excel-DDE payload our CSV test uses). Fixed in code (`75aa694`: payload assembled from parts, neutral hostile test ids, guard in `tests/test_hygiene.py`; see `docs/ENGINEERING_AUDIT.md`). The exact path `.pytest_cache\\v\\cache\\lastfailed` is still write-blocked by BitDefender on this machine; the restored file was moved out of the project (it lives under the session scratchpad in Temp). Clearing it needs a BitDefender exception for `.pytest_cache`. Harmless: only a pytest warning when a test fails.

Session log with the full what-worked / what-failed record: `~/.claude/session-data/2026-11-02-exposure-case-session.tmp`.

## Resuming in a new session

```bash
cd <path to this repo>
uv sync                      # pinned runtime and dev dependencies
git config core.hooksPath .githooks
sh scripts/check_all.sh      # every gate, including the tests
```

- Read `CLAUDE.md`, then this file's Submission checklist.
- API keys: `. $HOME\.secrets\tenable-env.ps1` (PowerShell) loads them per session along with `TENABLE_UA_VENDOR`; re-store with `powershell -File $HOME\.secrets\tenable-store.ps1` in a real terminal (not through `!`).
- The full export used for measurements lives in `data/raw/full1` (gitignored). Re-fetch with `scripts/fetch_tenable.py`.
- The research doc is outside the repo, in the parent folder. Keep it out.
