# Design decisions and roadmap

The decisions behind Exposure Case Builder, the scoring table and the tool list, and the work not yet done. How the code is put together is in `architecture.md`. The full list of limitations is in `LIMITATIONS.md`, and related tools are in `PRIOR_ART.md`.

## Decisions

| Decision | Choice | Why |
|---|---|---|
| Case unit (risk view) | Patch-type families (`* Local Security Checks`, `Windows : Microsoft Bulletins`) are one case per family. Every other plugin is one case per `plugin.id` | Plain per-plugin clustering gave 7,148 cases on a 160-host tenant, and the top 20 were near-duplicate KB plugins. The hybrid gives 815 |
| Fix packages (engineer view) | Key = normalized product (first CPE `vendor:product`) + fix type (from the solution's opening verb). Falls back to the plugin. Every active finding is in exactly one case and one package, and each links to the other | Security teams want risk-centred cases. Engineers want to know what to do and what it clears |
| Score | One transparent weighted sum with a component breakdown. KEV and VPR feed the exploit component | Explainable, and no ML |
| Two-list queue | `case_queue` returns single-vulnerability *threats* and patch *backlogs* separately | Large backlogs saturate the exploit component and would otherwise bury single exploited vulnerabilities |
| Impact wording | A package's totals are what it *contains* across its distinct actions. Only each action's own row says what it alone clears | Tenable's data does not say one update supersedes another |
| Disposition | `assigned`, `risk-accepted`, `false-positive`, `needs-info`. Append-only local JSONL, latest entry per item wins, needs `confirm=true`. Bulk views omit the free-text note | The human decides, and a stored note is replayed to a model |
| Fetch client | Standard-library `urllib`, not pyTenable | pyTenable needs Python >= 3.11 and 14 runtime dependencies for a four-endpoint fetch. See `PRIOR_ART.md` |
| Output locations | Absolute paths, default `~/.exposure-case/` | Nothing is ever written relative to the working directory |
| MCP SDK and Python | `mcp==2.3.0`. Python >= 3.10, tested on 3.10 and 3.14 | `from mcp.server.mcpserver import MCPServer` |

## Scoring (`scoring.py` is authoritative)

Total = the sum of component points (maximum 100). Every case and package returns the breakdown.

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

Ages are measured from the newest `last_found` in the data, never the wall clock. Ties break on id. The weights are a judgment, not a validated model.

## MCP tools (`server.py` is authoritative; `tests/test_skill.py` and `tests/test_listing.py` enforce it)

| Tool | Writes? | Purpose |
|---|---|---|
| `fleet_summary` | no | Totals, severity, case and package counts, KEV, data-quality notes |
| `case_queue` | no | Ranked cases as `threats` and `backlogs` (or one kind). `hide_dispositioned` reports how many it hid |
| `fix_queue` | no | Ranked fix packages. `order="coverage"` lists them in the greedy host-clearing order (a heuristic; the score rank is unchanged) |
| `case_file` | no | One case: score breakdown, facts, linked packages, vulnerabilities, hosts, timeline, limitations, disposition |
| `fix_package` | no | One package: Tenable's actions with what each clears, contained impact, hosts, CVEs, advisories, cases |
| `findings` | no | The real finding records behind a case or package, paged, so a narrative cites genuine ids |
| `trend_diff` | no | Comparison with an earlier saved export (`EXPOSURE_CASE_BASELINE`): counts per category, host overlap, data-quality counters, or a page of finding ids |
| `export` | with `write=true` and `confirm=true` | Markdown or CSV inline (size-capped). With a write, all formats go to the export directory |
| `record_disposition` | yes, `confirm=true` | One appended line in the decision log |

No tool accepts a file path. `confirm` is a convention: the client's tool-permission prompt is the real gate.

## Design principles

Every change is checked against these:

1. **Per-action accounting.** Each fix package lists every distinct Tenable action and what *it alone* clears. It never claims one update replaces another.
2. **Portable handoff.** An engineer can act on an export with no Tenable login: finding ids, scan uuids, solution text labelled as Tenable's, and the affected assets.
3. **Plain Vulnerability Management input.** It works from a saved export with ordinary read access, with no Tenable One or Lumin dependency.
4. **Open score.** One documented weighted sum with its breakdown. VPR is shown as one input.
5. **Read-only toward Tenable.** No tool changes a Tenable system. The only writes are two local files behind `confirm`.
6. **A decision record.** The append-only disposition log stays.
7. **Threats versus backlogs, linked both ways.** Keep the two queues and the links between cases and packages.

### Coverage order

`fix_queue(order="coverage")` (`coverage.py`). Findings are disjoint across packages, so the overlap that matters is **hosts**: a host can have urgent findings in several packages. An **urgent finding** is active, not info, and either critical, on CISA KEV, exploited by malware, or with a public exploit. Each step greedily picks the package that brings the most hosts to zero urgent findings. Ties go to the one removing the most urgent findings, then the one with the fewest distinct actions, then package id. It is a heuristic, not the shortest plan. "Cleared" means no urgent finding in this export.

### Trend diff

`trend_diff` compares the current export with an earlier one (`EXPOSURE_CASE_BASELINE`, an absolute directory; no tool takes a path). A finding is matched on `finding_id` plus `(asset_uuid, plugin_id, port, protocol)`. Mismatches are counted as `id_reuse` and `possible_rekeys` and are never merged. Each non-info finding falls in exactly one of these categories: `new_since_baseline`, `newly_visible`, `fixed_recorded`, `reopened`, `not_seen_rescanned`, `not_seen_not_rescanned`, `severity_raised`, `severity_lowered`, `still_active`. A missing finding is never called fixed. A synthetic baseline (`scripts/make_baseline.py`) is labelled as such.

## Testing strategy

There are unit tests for each module, MCP contract tests (a real server with a real SDK client), an end-to-end flow (fake Tenable, then the fetch script, the server, an export and a decision), golden-file tests for the exporters, drift guards (skill, listing, workflow gates), and the standards checker run over this repo. The coverage gate is 80%.

## Roadmap (not built)

- Trend: per-case and per-package deltas, a coverage-host delta, whether a recorded fix held (joined with dispositions), trend lines in exports, and an archive of earlier pulls. Not yet tested against two real pulls, and `finding_id` stability across pulls is undocumented by Tenable.
- Per-action plugin ids in fix packages.
- A decision-table tier (SSVC or BOD 26-04 style) beside the weighted score.
- Strict rejection of unknown tool arguments, and elicitation for writes.
- A per-field length cap on hostnames, OS strings and titles at the service boundary.
- A scripted evaluation set and an automatic check that narratives stay faithful to the tool results.
- An overall wall-clock deadline for a fetch, and per-field presence rates in `fleet_summary`.
- 0o700 permissions on exports and the decision log.
- CodeQL, branch protection, Dependabot updates, a gitleaks job in CI, signed tags and an SBOM.
- Moving the row builders out of `service.py`.
