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
exposure-case-builder/               (renamed from insider-case-builder on 2026-11-03; package is exposure_case)
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
| `fix_queue` | no | Ranked fix packages; `order="coverage"` lists them in the greedy host-clearing order (heuristic; the score rank is unchanged) |
| `case_file` | no | One case: score breakdown, facts, linked packages, vulnerabilities, hosts, timeline, limitations, disposition |
| `fix_package` | no | One package: Tenable's actions with what each clears, contained impact, hosts, CVEs, advisories, cases |
| `findings` | no | Real finding records behind a case or package, paged, so a narrative cites genuine ids |
| `trend_diff` | no | Compare with an earlier saved export (`EXPOSURE_CASE_BASELINE`): counts per category, host overlap, data-quality counters, or a page of finding ids |
| `export` | with `write=true` and `confirm=true` | Markdown / CSV inline (size-capped); all formats to the export directory |
| `record_disposition` | yes, `confirm=true` | One appended line in the decision log |

No tool accepts a file path. `confirm` is a convention: the client's tool-permission prompt is the real gate.

## Differentiation from Tenable's own features (decided 2026-11-03)

Tenable already groups fixes (Solutions view), opens Jira/ServiceNow tickets and ships an MCP server (Hexa AI), all on Tenable One / Lumin licensing; see `docs/PRIOR_ART.md`. Every change is checked against these guardrails, which are what the build offers that Tenable's documented features do not:

1. **Per-action accounting.** Each fix package lists every distinct Tenable action and what *it alone* clears. Tenable's docs never say how a solution is formed and warn that "remediating one may affect other plugins". Keep this visible in the case file, the fix package and the demo.
2. **Portable handoff.** An export an engineer can act on with no Tenable login and no Lumin license: finding ids, scan uuids, solution text labelled as Tenable's, affected assets. Do not add anything that makes an export depend on the console.
3. **Plain Vulnerability Management input.** Works from a saved export with ordinary read access (the documented minimum role). Say so in the README; never add a Lumin or Tenable One dependency.
4. **Open score.** One documented weighted sum with its component breakdown; never replace it with, or hide it behind, a Tenable-computed number. Show VPR as one input.
5. **Read-only toward Tenable.** No tool changes a Tenable system; the only writes are two local files behind `confirm`. Hexa's MCP server writes tickets, tags and scans.
6. **Decision record.** The append-only disposition log stays; Tenable documents only ticket status.
7. **Threats versus backlogs, linked both ways.** Keep the two queues and the shares between cases and packages.

### Coverage order (built 2026-11-03)

Status: built test-first (RED seen for the module, the service wiring, the exports, the scale test and the doc drift guards). Reviews run: code-reviewer (2 HIGH: quadratic cost, unfinished scope; both fixed), python-reviewer (approve; renames, keyword arguments, `Literal` schema, private attribute fixed), security-reviewer (no findings above LOW). Incremental gain updates replaced the full recomputation: 1,000 packages x 200 hosts out of 3,000 went from about 10 s to about 1.6 s, and a test checks the incremental order against a from-scratch recomputation on 200 random cases. Not done: moving row builders out of `service.py` (about 440 lines, over the 400 guideline, under the 800 maximum); a separate follow-up.

A second, additive ordering of fix packages, `coverage.py`. Findings are disjoint across packages, so finding-level marginal coverage is just a sum; the real overlap is **hosts** (a host has urgent findings in several packages). Case-level overlap was rejected: backlog cases span many packages, so nearly every step would clear zero cases and the tie-break would decide.

- An **urgent finding** is active, non-info, and critical, on CISA KEV, exploited by malware, or with a public exploit (one documented constant).
- Greedy, deterministic: at each step pick the remaining package with the best key: (1) most hosts newly at zero urgent findings, (2) most urgent findings removed, (3) fewest distinct fix actions, (4) package id. Effort is a tie-break only, never a divisor.
- Packages with no urgent findings get no step (`coverage: null`).
- Additive: the score rank is unchanged. `fix_queue` gains `order="score"|"coverage"` (default score) and a `coverage` object per row; `fix_package` gains `coverage`; the exports carry it.
- Wording: "applying every listed action in this package"; never that one update replaces another. "Cleared" means no urgent finding in this export, not that the host is secure. A greedy order is a heuristic, not the shortest plan; all-of host clearance is not classic set cover and has no approximation guarantee.
- Tests first: `tests/test_coverage.py` (empty, single, shared host, tie-breaks, input-order independence, FIXED and info excluded, sum of cleared hosts equals urgent hosts, frozen), then `test_service.py`, `test_server.py`, golden Markdown and an e2e on `data/sample`. The security-reviewer must run (new tool parameter).

### Trend diff (Phase 1 built 2026-11-03)

Status: Phase 1 is built test-first (RED seen at each step) and passes every gate. Reviews run on the uncommitted change: code-reviewer (2 HIGH, both fixed: an OPEN finding that came back REOPENED was hidden in `still_active`; a downgrade to informational was reported as a disappearance; also fixed: per-host cutoff for new versus newly visible, rescan measured against the host's own baseline time, host overlap and notes on every page, baseline refusals for info-only and empty inputs, protocol case, FIXED pairs excluded from `possible_rekeys`), security-reviewer (no CRITICAL or HIGH; fixed: ids from the export are one-lined, stripped of invisible characters and capped, and the instructions call them untrusted; the synthetic label also lives in the scan ids so deleting the marker file does not hide it; plugin output is not copied into a synthetic baseline; a malformed source fails cleanly; a `chunks` link into the data directory is refused), python-reviewer (approve; env leak in a test fixed). **Not acted on:** a lighter record type for the baseline to cut peak memory (the baseline is parsed in full, so peak is about twice one export, bounded by the ingest limits); UNC paths for the baseline (operator-controlled, same as `EXPOSURE_CASE_DATA`); a single source of truth for the category names (a test keeps `TrendCategory` and `CATEGORIES` in step); `_change`'s defensive guard and its test of a private function; a stale finding that appears and is FIXED between pulls is not reported. **Deferred:** extracting the row builders from `service.py` (476 lines, over the 400 guideline, under 800) as its own refactor commit.

Question it answers that one export cannot: what changed since the last pull. A single export already carries FIXED findings with dates; a second pull adds findings that appeared, appeared only because coverage grew, vanished without a recorded fix, or came back. Patch Shepherd diffs against the prior pull; this one credits that and differs in being finding-id based, read-only, and tied to the cases and packages.

- **Baseline:** optional env var `EXPOSURE_CASE_BASELINE` (absolute directory), resolved at startup like `EXPOSURE_CASE_DATA`. No tool takes a path. Loaded with `load_findings` and the same limits; refused if it is the data directory, if its newest observation is later than the current export's, or if no host appears in both; warned below 50% host overlap. Only the diff is kept; baseline records are dropped.
- **Identity:** a finding is matched on `finding_id` plus `(asset_uuid, plugin_id, port, protocol)`. Same id with a different second key counts as `id_reuse` and is treated as gone plus new; a different id with the same second key is counted as `possible_rekeys` and never merged. `finding_id` stability across real pulls is **unverified** (the sample ids are name-based UUIDs); test against two real pulls before the pitch.
- **Categories, each finding in exactly one (info findings excluded; FIXED on both sides or FIXED then absent ignored):** `new_since_baseline`, `newly_visible` (absent before, older `first_found`: coverage, not new risk), `fixed_recorded`, `reopened`, `not_seen_rescanned`, `not_seen_not_rescanned`, `severity_raised`, `severity_lowered`, `still_active`. A host counts as rescanned when its newest `last_found` in the current export is later than the finding's `last_found` in the baseline.
- **Wording:** never "fixed" for absence: "not present in the later export; Tenable recorded no fix". Host overlap is shown beside every count. A synthetic baseline is labelled.
- **Output:** a new read-only tool `trend_diff(category, limit, offset)` returning counts, host overlap, data-quality counters and notes, or paged rows of ids and numbers for one category. No Tenable free text. Without a baseline it returns `configured: false`.
- **Modules:** `baseline.py` (load and validate), `trend.py` (pure `diff`, frozen dataclasses). `service.py` gets a few lines of glue only.
- **Phase 1 (this session):** fleet categories, baseline validation, the tool, `scripts/make_baseline.py` (deterministic synthetic baseline from the sample, gitignored output), docs and drift guards, reviews, commit. **Phase 2:** per-case and per-package deltas, coverage-host delta. **Phase 3:** whether a recommended fix held (disposition join), trend lines in exports, an archive picker. Optional Phase 0: move row builders out of `service.py`.

Claims to avoid: that Tenable lacks fix grouping, ticketing or an MCP server. Claims to verify before making: anything about how Tenable forms a solution (check `GET /solutions` on a Lumin tenant if one is available). Candidate gaps to close, not built: a trend diff against the previous pull (Patch Shepherd does this).

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

State on 2026-11-03: employer approval obtained (the user's statement; the Contribution Agreement still has to be read and its acceptance time recorded by the submitter). The team is registered; its registration text describes the earlier idea, so say so in the PR description (the rules and contributing pages say nothing about changing a project after registration). `origin` is `github.com/SpookyFox9/exposure-case-builder` and was last pushed at `d476dca`; the later commits are local until pushed, and the Exchange reviews the pushed repository. Tag `v0.1.0` exists on `51bc047`, before the coverage order, trend diff and sample fix; the Exchange does not need a tag, so either leave it or make a new release (`v0.2.0`, which needs a version bump) rather than rewrite a published tag.

1. Confirm eligibility: the rules require registering at info.tenable.com/2026-SWARM-GLOBAL.html before it closed (Nov 1), joining the Discord, and every contributing member accepting the CyberAgents Contribution Agreement. Read the agreement (not fetched here): it covers licence, authority including "any required employer permission", and non-infringement.
2. ~~Ask on Discord~~ **Decided 2026-11-03 not to ask** (the user's call: other teams are in the same position and the organizers would have announced a problem). Open, unverified items: what the **Submission Deadline** is (the rules use the term but never define it), how to **notify Tenable** of the submission, and that the registration text predates the pivot (say so in the PR description).
3. Run one live Claude Code session on `data/sample` (`claude mcp add`; see the playbook). Keep `export` and `record_disposition` on "ask".
4. Create the public repository on the personal account and push. The listing assumes `github.com/SpookyFox9/exposure-case-builder`.
5. Tag `v0.1.0`.
6. Fork `tenable/cyberagents-exchange`; copy `docs/exchange/mcp-server-listing.md` to `mcp-servers/exposure-case-builder.md`; set `contribution_agreement_date` to your own acceptance time, the final `github_url` and `date_added`; run the Exchange's own `uv run ./validator.py`; open the PR titled `Add listing: Exposure Case Builder` with the acceptance statement in the description.
7. Pitch (Thu Nov 5, selected teams, about 15 minutes) and awards (Fri Nov 6): build the demo around one live case walk-through on the sample.

## Key dates (organizers' message, pasted by the user 2026-11-03; all times ET)

Registration and rosters closed Mon Nov 2, 11:59 PM. Tutorial on Zoom Tue Nov 3, 11 AM (passed). **Wed Nov 4, 2 PM: "open your PR to the CyberAgents Exchange"** (exact wording, confirmed by the user 2026-11-03; whether it is the deadline or the time the window opens is ambiguous; the 4 PM pitch selection suggests a deadline; the user plans to open it 12-1 PM ET). After opening, per the organizers on Discord: "Once your PR is open, DM me (@Bee) the link or email it to SWARM@tenable.com. That's how we know which PR is your team's submission." Wed Nov 4, 4 PM: teams selected for pitch day are emailed. Thu Nov 5: pitch day for selected teams (details to follow). Fri Nov 6, 11 AM: awards on Zoom. Links given: how to submit (exchange.tenable.com/contributing/), rules (exchange.tenable.com/swarm-global-rules-nov2026/). Whether the user registered before the cutoff is theirs to confirm.

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
- Whether Wed Nov 4, 2 PM ET ("open your PR to the CyberAgents Exchange", per the organizers' key-dates message the user pasted on 2026-11-03) is a hard cutoff or only when the PR window opens. The message does not use the words "Submission Deadline".
- The minimum Tenable role for exports is now documented (Basic [16] + Can View on assets, per developer.tenable.com export reference); the workbench call's minimum was not checked.
- The cause of the 41 count mismatches against Tenable's own numbers.
- Whether MCP elicitation is supported by the client (not used; `confirm` plus the client prompt is the gate).
- The Chokepoint Finder repositories (only their listing files were read).

## Status

**Rehearsal, 2026-11-03 evening.** The live demo was run twice from a fresh clone of the public repo (`exposure-case-builder-demo`). Run 1 (Sonnet 5.5) used a stale skill copy in `~/.claude/skills` (Nov 2, before the coverage and trend sections), which explains its claim that `trend_diff` "gives counts only"; DEMO.md setup now copies the skill and moves the disposition log aside. Run 2 (Opus 5.5, current skill) fixed that and showed exports in full. Still wrong in run 2, now fixed: (a) Claude reordered coverage steps 5-7 and summed their counts, which only hold after steps 1-4 (skill rule plus a sentence in the coverage note); (b) it read `data_quality` "25 of 50" as records, when it is plugins with every gap below Tenable's count (`fleet_summary` now returns `compared_unit`, the direction counts and a note; the sample holds 25 of the 41 plugins that differ on the full export, 99.1% match there). Also added skill rules: claim only what tools returned, no owner claims, show exports as returned. Code review (code-reviewer agent): no CRITICAL or HIGH; the MEDIUM findings were fixed (the summary is now a pure `quality_summary` tested with gaps below, above and straddling Tenable's count, the note points at both direction counts, a brittle below-plus-above-equals-all test was removed, and a missing `plugins.json` is tested); LOW items fixed except two left on purpose: the DEMO figures for this sample can go stale if the sample changes (dated instead), and `matched_on_instances_only` is not surfaced in `fleet_summary`. Run 3 (Opus 5.5, all seven steps, about 14 minutes) was clean on the earlier issues and found two more, now fixed: the synthetic baseline marked findings FIXED although Tenable dates them as reopened before the baseline date (the generator now flips a state only when Tenable's own fix or resurfaced date is after the baseline; step 5 figures are now fixed as recorded 9 and reopened 17), and triage claimed no baseline was configured without calling `trend_diff` (skill rule). **Readiness check (Phase B, 2026-11-03 night).** `pip-audit` over the 182 locked packages: no known vulnerabilities. Full private export (19,437 findings): load and build about 1 s, every tool under 10 ms. Found and fixed: `fix_package` answers reached about 190,000 characters on the full export (uncapped CVEs, advisories, plugin ids) and `case_file` about 127,000 (every finding id in every timeline entry); both are now capped with `_total` counts (worst case over all 200 packages 15,000 and over all 815 cases 24,000 characters), advisories and action solutions are shortened to 500 characters, and exports stay complete (tested). `export` is now annotated destructive and idempotent (write=true replaces same-named files). Reviews: code-reviewer and security-reviewer found no CRITICAL or HIGH; their MEDIUM items were fixed; left for later: a per-field length cap (about 256 characters) on hostnames, OS and titles at the service boundary, and the 500 maximum on `max_hosts`/`max_events`. GitHub settings read (not changed): secret scanning and push protection on; Dependabot alerts, branch protection and code scanning off; no `SECURITY.md`. **Readiness check (Phase C, against the research checklist `../Exposure Case Builder_ CyberAgents Exchange Readiness Checklist (Nov 2026).md`).** Done: `SECURITY.md` (private vulnerability reporting, scope, threat-model table; reporting must be switched on in the repo settings by the owner); EPSS shown per vulnerability beside KEV and VPR in case files and the case Markdown (Tenable reports it as a percentage, 0-100; bounded at ingest; labelled "EPSS %"), deliberately not scored (FIRST guidance; a reviewer suggested a 0-1 bound, which the tests showed would have dropped every real value); README gained the `permissions.ask` snippet, annotations-are-hints, the protocol revision (tested against the SDK constant) and "heuristic, not a measure of risk"; the committed sample is split into two files under 900 KB (Exchange reviewers flag files over 1 MB), regenerated and verified identical, with `data/sample/** text eol=lf`; a test proves a misspelled confirm flag cannot write. Already met: Exchange gating items E1-E10, BOD 22-01 not cited, annotations, neutralization tests, capped answers, hashed lockfile, `pip-audit` clean, pinned CI actions, JSON size and recursion caps, fetch hardening, gitleaks over all refs clean. Deferred after the PR: rejecting unknown tool arguments (the SDK ignores them; writes still need confirm=true exactly), elicitation for writes, a scripted eval set and an automatic narrative-faithfulness check, CodeQL, branch protection, Dependabot updates, signed tags and an SBOM, a per-field length cap on hostnames and OS strings. Reviews: code-reviewer found one HIGH (the `.gitattributes` rule was glued to the previous line and inactive), fixed; security-reviewer no CRITICAL or HIGH; MEDIUM wording items in `SECURITY.md` fixed. **Exchange quality-review skill (`cyberagents-exchange-quality-review`, run read-only with no installs, 2026-11-03 night).** Verdict: ready to submit; all rejection gates pass; 0 CRITICAL or HIGH; every active finding on the full export is in exactly one case and one package. Fixed: invisible and bidi characters reached the model in tool answers (now stripped at ingest, with a fast path that keeps the full load at about 1.2 s), the OS list skipped the 4,096-character cap, upper-case URLs and e-mail addresses could still form links in Markdown, the fetch script had no retry (now bounded retry with capped backoff on 429/502/503/504, never repeating the job-creating POST after a 5xx), a malformed failed-chunk list crashed the fetch script with a traceback, an export with no findings raised a bare ValueError, the README misstated the dev dependencies and their licences, and there was no cleanup guidance for `~/.exposure-case/`. Their reviews (code-reviewer, security-reviewer): no CRITICAL or HIGH; fixed: finding and asset ids with hidden characters are now refused at ingest (stripping would break the trace to source; the full export still loads), a non-ASCII `Retry-After` no longer crashes the fetch script, and the e-mail pattern is anchored so it stays linear. Deferred: an overall wall-clock deadline for a fetch (each request and the poll count are already bounded), per-field presence rates in `fleet_summary` (to notice a renamed optional Tenable field), 0o700 permissions on exports and the log, and a gitleaks job in CI (with CodeQL). Not acted on: per-action plugin ids in fix packages (Claude inferred the action-to-case column from version numbers; correct here, but inferred), deferred until after the PR. The CI failures on earlier pushes (a Linux-only cleanup error masking `FetchError`, and a 5 s timing limit on a slow runner) were fixed in `c8ee9f1` and `7abc114`. Contribution Agreement accepted by the submitter at 2026-11-03T22:24:56Z; repo made public by the submitter; the Exchange validator passed on the fork branch `add-exposure-case-builder` (PR not yet opened).

Last updated: 2026-11-03 afternoon. Since the entry below: the coverage order (`7f83989`), the trend diff (`2326dd6`) and a sample fix (`10bd9bd`, below) landed; 702 tests pass at 97% branch coverage; full-history `gitleaks` over 26 commits found nothing; `docs/DEMO.md` is the pitch walk-through. **Sample fix:** the committed sample had been trimmed before the fix-package work and carried no solution text, CPE, CVE, VPR or KEV, so every package built from it was "unspecified" with one action; the trimmer now keeps those public plugin fields (same 1,125 findings, 154 hosts, 50 plugins; 1.1 MB to 1.6 MB). On the full local export the coverage order builds in about 1.1 s with load: 117 steps over 115 urgent hosts, 18 steps to reach half of them, and the first step is 93 distinct updates for 8 hosts. The Exchange validator was not run (it executes code from the Exchange repo, which the harness blocked); the listing was checked by hand against its models, and only `contribution_agreement_date` is left for the submitter. Earlier status (2026-11-02, late afternoon, HEAD `75aa694` or later). 557 tests pass at 96% branch coverage on Python 3.10 and 3.14; `sh scripts/check_all.sh` (ruff, black, mypy, bandit, standards checker, coverage gate) is clean; full-history secret scan clean. Everything buildable without the user is built; the open items are the submission checklist above.

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
- **Where things stood at the end of the 2026-11-03 session** (everything below is committed; nothing is pending in the working tree): coverage order and trend diff built and reviewed; sample fixed; `docs/DEMO.md` written; key dates recorded (Exchange PR due Wed Nov 4, 2 PM ET). **Next, in order:** (1) rename the folder to `exposure-case-builder` (the user does this; afterwards delete `.venv`, run `uv sync --frozen`, re-register the MCP server with the new paths, copy the old Claude project memory folder across); (2) run the live demo session from `docs/DEMO.md` and fix anything that reads badly, mainly in `skills/exposure-case/SKILL.md`; (3) ask on Discord whether Nov 4, 2 PM ET is a hard cutoff and how to notify Tenable, and mention that the registration text predates the pivot; (4) the user reads and accepts the Contribution Agreement and sets `contribution_agreement_date` (never fill it in for them); (5) fork `tenable/cyberagents-exchange`, branch `add-exposure-case-builder`, copy `docs/exchange/mcp-server-listing.md` to `mcp-servers/exposure-case-builder.md`, run the Exchange's `validator.py` (the harness will not run it for the assistant), open the PR titled `Add listing: Exposure Case Builder` with the acceptance statement and a one-line note about the changed idea; (6) real second `fetch_tenable.py` pull if possible, to test finding-id stability. Tag `v0.1.0` is left as published; a new tag would be `v0.2.0` after a version bump.
- API keys: `. $HOME\.secrets\tenable-env.ps1` (PowerShell) loads them per session along with `TENABLE_UA_VENDOR`; re-store with `powershell -File $HOME\.secrets\tenable-store.ps1` in a real terminal (not through `!`).
- The full export used for measurements lives in `data/raw/full1` (gitignored). Re-fetch with `scripts/fetch_tenable.py`.
- The research doc is outside the repo, in the parent folder. Keep it out.
