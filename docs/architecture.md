# Architecture

How Exposure Case Builder is put together and why. The task list and status are in `PLAN.md`.

## Purpose and shape

A Tenable Vulnerability Management export is thousands of findings. Two groups need different things from it:

- the **security team** needs to know what is risky and why it ranks where it does;
- the **people who fix things** need to know what to do, what it clears, and on which hosts.

So the same findings are presented as two linked views: **cases** (risk) and **fix packages** (remediation). A deterministic engine builds both. Claude writes the cited narrative from the engine's results. The human analyst decides and records the decision. Code never issues a verdict, and Claude never invents a number.

```
 Tenable VM (cloud.tenable.com)
        |  scripts/fetch_tenable.py   <- the ONLY network path (GET/POST over HTTPS, no redirects)
        v
  data/raw/<export>/chunks/*.json, plugins.json        (gitignored)
        |  ingest.py        validate, bound, normalize -> FindingRecord (frozen)
        v
  cluster.py -> cases        fixes.py -> fix packages        (every active finding in exactly one of each)
        |                          |
        +------- links.py ---------+     scoring.py ranks both with one weighted sum
        |
  case.py (CaseFile / PackageView)   timeline.py   reconcile.py
        |
  report_md.py + export.py  -> Markdown / CSV / JSON          disposition.py -> append-only log
        |
  service.py  Workspace: every tool answer as capped JSON
        |
  server.py   stdio MCP server (8 tools)  <---- Claude Code + skills/exposure-case/SKILL.md
```

## Modules and responsibilities

| Module | Responsibility |
|---|---|
| `ingest` | Read saved chunks; validate and bound everything (file, total and record limits, known severities and states, tolerant optional fields); produce frozen `FindingRecord`s |
| `cluster` | Cases: one per patch family, one per other plugin; info findings excluded |
| `fixes` | Fix packages: normalized CPE product plus fix type read from the solution verb; per-action and contained impact |
| `coverage` | An additive greedy order over fix packages by hosts newly brought to zero urgent findings; the score rank is untouched. Findings are disjoint across packages, so the overlap that matters is hosts (see "Why these choices") |
| `links` | Two-way links with shares; refuses to build if the two views disagree about which findings exist |
| `scoring` | The only place weights live; ages anchored to the data, not the clock |
| `timeline`, `reconcile` | Dated events from Tenable's own dates; a trust check against Tenable's plugin counts |
| `case` | `CaseFile` (analyst) and `PackageView` (engineer), plain deterministic data |
| `report_md`, `export` | Rendering and the atomic file writers; `text_safety` neutralizes all Tenable text |
| `disposition` | The decision log: fixed vocabulary, bounded fields, append-only, tolerant reads |
| `service`, `server` | The tool layer; `service` is testable without a protocol, `server` is a thin wrapper |
| `common`, `schema` | Shared severity order and helpers; `Evidence`, the type every claim traces through |

## Invariants (each is tested)

1. Every active, non-info finding belongs to exactly one case and exactly one fix package; `links` raises otherwise.
2. Every number in a case or package traces to finding ids, and the `findings` tool returns the real records so a narrative cites genuine ids.
3. Output is deterministic: no wall-clock time, stable ordering, ids that never depend on input order.
4. A package's totals are what it *contains*; only an action's own row says what that action alone clears.
5. Nothing is written except behind `confirm=true`, to a fixed absolute location, atomically.
6. Tenable text never reaches a document as markup, a link or a formula, and never reaches the model as an instruction.
7. The engine and the server make no network calls.

## Trust boundaries

- **Tenable -> fetch script:** HTTPS to one host; redirects refused (they would forward the API keys); response, chunk-count and export-id limits; keys only from environment variables, held in an object whose `repr` hides them.
- **Disk -> ingest:** every file is untrusted: size caps, strict UTF-8 and nesting handling, record-level validation with the file and index in every error.
- **Engine -> documents and model:** `text_safety` escapes Markdown and HTML, turns bare URLs into inert code spans, prefixes spreadsheet formulas, and strips invisible and bidirectional-override characters. Plugin output is never returned by any tool. Stored analyst notes appear only in detail views, labelled as untrusted text.
- **Model -> tools:** all arguments are range-checked and enum-typed; item ids are looked up in the loaded export; there is no path parameter. `confirm` and `write` are strict booleans, but `confirm` is a convention: the client's tool-permission prompt is the real gate.

## Why these choices

- **Two views, not one.** A single risk-centred list buries the fix; a single fix-centred list hides the threats. Linking them lets each reader start from their own question.
- **Two queue lists.** KEV is common, so large patch backlogs saturate the exploit component and would outrank an exploited single vulnerability. Separate lists keep both visible without changing the approved weights.
- **Fix type from the solution's opening verb, not `has_patch`.** `has_patch` is true for 98% of plugins, including "Disable J-Web". The verb is the usable signal.
- **Coverage order counts hosts, not findings or cases.** Each finding is in exactly one package, so finding-level marginal coverage is a plain sum in any order. Case-level overlap was rejected: backlog cases span many packages, so nearly every step would clear no case and the tie-break would decide. A host is clear only when every package that touches it is applied (an all-of condition, not classic set cover), so a package's gain can rise as others are applied and the greedy has no approximation guarantee. Gains are updated only for packages that share a host with the one just placed. The order is a heuristic and the tool answer says so.
- **Stdlib engine, one runtime dependency.** The engine is small enough that a library would add more surface than it removes; `mcp` is needed to speak the protocol. pyTenable was evaluated and declined (`PRIOR_ART.md`).
- **A save-then-analyse split.** The fetch script writes files; everything else reads them. The analysis is reproducible, offline and testable against a committed sample.

## Known limits

Weights are a judgment, not validated; fix grouping is heuristic (first CPE, solution verb) and does not infer that one update supersedes another; near-duplicate plugin cases remain in the case view; the timeline has real fixed/reopened dates for only a minority of findings; tested on one tenant (160 hosts) on Windows 11. The README lists them for users.

## Extending

A new fix-type rule belongs in `fixes.classify_fix` with a test row; a new score component in `scoring.WEIGHTS` plus a `_component` function and a golden update; a new tool in `server._register_*_tools`, `service.Workspace`, `docs/exchange/mcp-server-listing.md` and `skills/exposure-case/SKILL.md` (the drift-guard tests fail until all four agree). Run `sh scripts/check_all.sh` before committing.
