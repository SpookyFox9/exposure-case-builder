# Prior art and positioning

The engineering workflow requires a search for existing work before building (step 0). This was **not done before the build started**; it was done on 2026-11-02 as part of the rules audit (`ENGINEERING_AUDIT.md`). This page records what it found and how we position the project.

## Method and limits

Read from `tenable/cyberagents-exchange` on 2026-11-02: the directory listings of `mcp-servers/` (25 files), `skills/` (about 88), `agents/` (about 22) and `playbooks/` (6), then about 35 listing files in full: every vulnerability-management, prioritization, triage, remediation and plugin-lookup listing found, plus the closest competitors. The Exchange's own browse page says "Browse all 127", which does not obviously reconcile with those counts, and the directory pages may be truncated. **Listing files describe a project; the linked repositories were not opened.** A claim below that a feature is "not seen" means not described in the listings read, not that it does not exist.

## Closest existing listings

| Listing (author, tier) | What it does | How it groups / ranks | Fixer handoff | Records a decision |
|---|---|---|---|---|
| **Patch Shepherd** (kstrycharz, contributed) | Clusters Tenable VM findings into root-cause remediation campaigns | Groups by shared solution text, falling back to finding name when the text is generic; scores "VPR x asset criticality, boosted for Critical/High"; keyword routing to an owning team | Analyst worklist, manager update, executive summary (JSON, CSV, Markdown); trend diff against the archived prior pull | No |
| **Remediation Priority & Impact Agent** (smjennings, **vetted**) | "What should I fix today?" briefing via the Tenable Hexa MCP | Asset Exposure Score, confirmed exploitation, VPR, criticality, attack paths; Fix FIRST / NEXT / SOON | Ready-to-paste change tickets per host | No |
| **Chokepoint Finder** family (tarhou: agent, skill, MCP server, playbook) | Collapses findings into the actions that fix them and solves for the shortest ordered shortlist | Groups by a synthesized "action" (a patch, image, IAM role...); greedy weighted maximum coverage over an action-to-findings matrix, so overlap is credited once | Ticket-ready payload, plan with a SHA-256 hash, verification receipt | Records that approved steps were executed, bound to a plan hash |
| **Exposure Response Consultant** (dpickenstenable) | Recommends the top 10 "Exposure Response Initiatives" | Archetype grouping with an Impact Score from asset count, AES and business risk | Markdown, HTML, JSON, asset CSVs for WSUS/SCCM/ServiceNow | No (writes tags to Tenable) |
| **Evidence-Backed Vulnerability Investigator** (infosecloudninja007) | Matches findings to advisories deterministically, then asks Claude for REMEDIATE / RECAST / MANUAL_REVIEW | Not Tenable-connected; exact-CVE, product/version and keyword matching | JSON or Markdown export | Analyst approves, rejects or overrides, saved locally |
| **Tenable CTEM MCP** (mrovere1) | 19 CTEM maturity indicators and MTTR | Aggregates on the server; every number carries its filter and sample size | Reports | No |
| BOD 26-04 Risk Tiering, Tenable SC SLA Triage, Tenable VPR MCP, Exposure Impact Simulator, Quick Wins dashboard, community Tenable MCP server (58 tools, via pyTenable), navi / navi-mcp | Tiering, SLA ageing, VPR-versus-CVSS views, what-if AES, executive plans, general Tenable operations | Varied (CISA SSVC table, VPR, heuristics) | CSV / HTML / dashboards | No |

## Overlap with this project

| Feature | Already covered elsewhere? |
|---|---|
| Cluster findings into root-cause groups with a transparent score | **Yes**: Patch Shepherd (solution text), the Chokepoint family (synthesized actions), Exposure Response Consultant |
| Ranked fix list with tickets | **Yes**: Remediation Priority & Impact Agent (vetted), Patch Shepherd |
| Markdown / CSV / JSON handoffs | **Yes**: several |
| Deterministic, read-only core | **Yes**: BOD 26-04, Tenable CTEM MCP, SC SLA Triage, VPR MCP |
| A local analyst decision record | **Partly**: Evidence-Backed Investigator (local approve/reject/override), Chokepoint (execution receipts) |
| Two ranked lists, single-vulnerability *threats* versus patch-family *backlogs* | Not seen |
| Fix packages keyed by normalized **CPE product** plus a **fix type** read from the solution verb, listing each distinct Tenable action with what *it alone* clears | Not seen (Patch Shepherd keys on solution text; Chokepoint on synthesized actions) |
| Cases and packages linked **both ways** with shares, and every finding in exactly one of each | Not seen |
| An **append-only local disposition log tied to Tenable VM findings** with a confirm gate | Not seen |
| An MCP server whose every write is gated and whose Tenable text is neutralized in every export | Not seen |

## Positioning (use this in the README and the pitch)

- Do **not** claim novelty. Say instead: *similar problems are addressed by Patch Shepherd, the Chokepoint family and the vetted Remediation Priority & Impact Agent; this project's difference is a two-view design (risk cases and CPE-keyed fix packages, linked both ways), a threats-versus-backlogs queue, a deterministic stdlib engine with an MCP surface, and a local decision log.*
- The honest gap against the Chokepoint family: it credits shared fixes **once** across the whole shortlist (marginal coverage). Our packages are disjoint by construction, so there is no double counting, but we do not search for the shortest ordered set of actions. A greedy marginal-coverage ordering over fix packages is a natural next step and is **not built**.
- Patch Shepherd diffs against the previous pull to show trend. We have no cross-run trend.

## Reuse

No code was reused. Patch Shepherd, the Chokepoint family and most others are MIT; `tenable-sc-mcp-server` is GPL-3.0-only and `sc-ai-agent` is BSD-3-Clause, so reusing those would carry obligations. Ideas acknowledged: clustering by shared fix (Patch Shepherd, Chokepoint), marginal coverage (Chokepoint), aggregation with provenance (Tenable CTEM MCP).

## Library decision: pyTenable

Evaluated 2026-11-02 from PyPI metadata: pyTenable 26.10.1, MIT, **requires Python >= 3.11**, 14 runtime dependencies (requests, pydantic, marshmallow, gql, graphql-core, python-box, arrow and others). Our fetch path is four endpoints and the project promises Python >= 3.10 and one runtime dependency. **Decision: keep the stdlib client.** Revisit if the fetch surface grows (pagination, retries, other Tenable products). The community Tenable MCP server builds on pyTenable.

## Not read, worth reading before the pitch

The Chokepoint Finder repositories; `compliance-prioritizer`, `tenable-tag-optimizer`, `tenable-exposure-alert-notifier`, `cyber-risk-quantifier`, `navi-skills`, `tenable-sentinelone-patch-remediation-bridge`.
