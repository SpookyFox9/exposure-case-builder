"""Markdown reports: the analyst case file and the engineer handoff, built from small per-section functions."""

from __future__ import annotations

import math
from collections.abc import Iterable

from .case import SCOPE_NOTE, CaseFile, PackageView
from .common import plural
from .fixes import FixAction, HostLine
from .text_safety import md_cell, md_code, md_text

DEFAULT_MAX_HOSTS = 25
DEFAULT_MAX_ACTIONS = 15
DEFAULT_MAX_REFS = 25
DEFAULT_MAX_VULNS = 15
DEFAULT_MAX_EVENTS = 40
DEFAULT_MAX_CASES = 10
EVENT_LABELS = {
    "first_seen": "First seen",
    "fixed": "Fixed",
    "reopened": "Reopened",
    "last_seen_reopened": "Last seen (reopened)",
    "last_seen_fixed": "Last seen before fix",
}
_EN_DASH = chr(0x2013)


def format_share(share: float) -> str:
    """Floored to 0.1%: a near-complete share never reads as 100%, a tiny one never as 0%."""
    if share <= 0:
        return "0.0%"
    if share >= 1:
        return "100.0%"
    pct = math.floor(share * 1000) / 10
    return "under 0.1%" if pct < 0.1 else f"{min(pct, 99.9):.1f}%"


def _table(header: list[str], rows: list[list[object]], right: frozenset[int] = frozenset()) -> list[str]:
    align = ["---:" if i in right else "---" for i in range(len(header))]
    lines = ["| " + " | ".join(header) + " |", "| " + " | ".join(align) + " |"]
    lines += ["| " + " | ".join(md_cell(c) for c in row) + " |" for row in rows]
    return lines


def _host_rows(hosts: Iterable[HostLine]) -> list[list[object]]:
    return [
        [
            h.hostname or h.asset_uuid,
            h.ipv4,
            h.operating_system,
            h.findings,
            h.worst_severity,
            h.oldest_first_found.date().isoformat(),
        ]
        for h in hosts
    ]


def _host_section(hosts: tuple[HostLine, ...], max_hosts: int, csv_hint: bool = True) -> list[str]:
    header = ["Host", "IP", "OS", "Findings", "Worst severity", "First seen"]
    lines = _table(header, _host_rows(hosts[:max_hosts]), frozenset({3}))
    if len(hosts) > max_hosts:
        tail = "the full list is in the CSV" if csv_hint else "the full list is in the JSON"
        lines += ["", f"Showing {max_hosts} of {len(hosts)} hosts; {tail}."]
    return lines


def _capped_list(items: tuple[str, ...], cap: int, code: bool = False) -> list[str]:
    render = md_code if code else md_text
    lines = [f"- {render(i)}" for i in items[:cap]]
    if len(items) > cap:
        lines.append(f"- plus {len(items) - cap} more in the JSON")
    return lines or ["- none recorded"]


def _assemble(sections: list[list[str]]) -> str:
    """Sections separated by one blank line, with a trailing newline."""
    lines: list[str] = []
    for index, section in enumerate(sections):
        if index:
            lines.append("")
        lines.extend(section)
    lines.append("")
    return "\n".join(lines)


# --- engineer handoff ---


def _action_rows(actions: Iterable[FixAction]) -> list[list[object]]:
    return [
        [
            a.solution,
            a.plugins,
            a.hosts,
            a.worst_severity,
            format_share(a.critical_share) if a.critical_findings else _EN_DASH,
        ]
        for a in actions
    ]


def _package_header(view: PackageView) -> list[str]:
    reasons = "; ".join(md_text(r) for r in view.priority_reasons)
    return [
        f"# Fix: {md_text(view.package.title)}",
        "",
        (
            f"Package {md_code(view.package.package_id)} · priority #{view.rank} "
            f"(score {view.score.total:.1f}/100) · data as of {view.as_of.date()}"
        ),
        "",
        f"**Why it ranks here:** {reasons}.",
    ]


def _package_actions(view: PackageView, max_actions: int) -> list[str]:
    header = [
        "Action (Tenable solution)",
        "Vulnerabilities",
        "Hosts",
        "Worst severity",
        "Fleet criticals this action alone clears",
    ]
    actions = view.package.actions
    lines = ["## What to do", "", md_text(SCOPE_NOTE), ""]
    lines += _table(header, _action_rows(actions[:max_actions]), frozenset({1, 2, 4}))
    if len(actions) > max_actions:
        lines += ["", f"plus {len(actions) - max_actions} more actions in the CSV and JSON."]
    return lines


def _package_impact(view: PackageView) -> list[str]:
    imp = view.package.impact
    severities = ", ".join(f"{k} {v}" for k, v in sorted(imp.by_severity.items())) or "none"
    return [
        "## Impact (contained in this package)",
        "",
        (
            f"- {plural(imp.actions, 'distinct action')}, {plural(imp.plugins, 'vulnerability', 'vulnerabilities')}, "
            f"{plural(imp.findings, 'finding')} on {plural(imp.hosts, 'host')}"
        ),
        f"- Findings by severity: {severities}",
        (
            f"- Exploitation: {imp.exploitable_findings} with a public exploit, {imp.malware_findings} exploited by "
            f"malware, {imp.kev_findings} on the CISA KEV list"
        ),
        f"- Contains {format_share(imp.critical_share)} of the fleet's critical findings",
    ]


def _package_references(view: PackageView, max_refs: int) -> list[str]:
    return [
        "## References",
        "",
        "CVEs:",
        *_capped_list(view.package.cves, max_refs),
        "",
        "Advisories (shown as text, not links):",
        *_capped_list(view.package.advisories, max_refs, code=True),
    ]


def _package_cases(view: PackageView, max_cases: int) -> list[str]:
    lines = ["## Cases this relieves", ""]
    lines += [
        f"- {md_code(c.other_id)} {md_text(c.title)}: {plural(c.findings, 'finding')} "
        f"({format_share(c.share)} of this package)"
        for c in view.cases[:max_cases]
    ] or ["- none"]
    if len(view.cases) > max_cases:
        lines.append(f"- plus {len(view.cases) - max_cases} more cases in the JSON")
    return lines


def _package_sources(view: PackageView) -> list[str]:
    return [
        "## Source records",
        "",
        (
            f"{plural(len(view.package.active), 'Tenable finding ID')} support this package; "
            "they are listed in the JSON export (`evidence_ids`)."
        ),
        "",
        "Hostnames, IP addresses and similar identifiers in this dataset are masked.",
    ]


def package_markdown(
    view: PackageView,
    max_hosts: int = DEFAULT_MAX_HOSTS,
    max_actions: int = DEFAULT_MAX_ACTIONS,
    max_refs: int = DEFAULT_MAX_REFS,
    max_cases: int = DEFAULT_MAX_CASES,
) -> str:
    return _assemble(
        [
            _package_header(view),
            _package_actions(view, max_actions),
            _package_impact(view),
            ["## Affected hosts", "", *_host_section(view.package.hosts, max_hosts)],
            _package_references(view, max_refs),
            _package_cases(view, max_cases),
            _package_sources(view),
        ]
    )


# --- analyst case file ---


def _case_header(cf: CaseFile) -> list[str]:
    return [
        f"# Case: {md_text(cf.title)}",
        "",
        (
            f"Case {md_code(cf.case_id)} · {md_text(cf.kind)} · rank #{cf.rank} "
            f"(score {cf.score.total:.1f}/100) · data as of {cf.as_of.date()}"
        ),
    ]


def _case_score(cf: CaseFile) -> list[str]:
    rows = [[c.name, f"{c.points:.1f}", c.weight, c.detail] for c in cf.score.components]
    return ["## Score breakdown", "", *_table(["Component", "Points", "Max", "Why"], rows, frozenset({1, 2}))]


def _case_fixes(cf: CaseFile) -> list[str]:
    rows = [[f"{f.title} ({f.other_id})", f.findings, format_share(f.share)] for f in cf.fixes]
    table = _table(["Package", "Findings", "Share of this case addressed"], rows, frozenset({1, 2}))
    return ["## Fix packages that address this case", "", *(table if rows else ["None."])]


def _case_vulnerabilities(cf: CaseFile, max_vulns: int) -> list[str]:
    header = ["Vulnerability", "CVEs", "Severity", "Hosts", "KEV", "VPR", "Tenable fix text"]
    rows: list[list[object]] = [
        [
            v.name,
            ", ".join(v.cves[:3]),
            v.severity,
            v.hosts,
            "yes" if v.on_cisa_kev else "",
            "" if v.vpr_score is None else v.vpr_score,
            v.solution,
        ]
        for v in cf.vulnerabilities[:max_vulns]
    ]
    lines = ["## Top vulnerabilities", "", *_table(header, rows, frozenset({3}))]
    if len(cf.vulnerabilities) > max_vulns:
        lines += ["", f"Showing {max_vulns} of {len(cf.vulnerabilities)} vulnerabilities; the rest are in the JSON."]
    return lines


def _case_timeline(cf: CaseFile, max_events: int) -> list[str]:
    events = cf.timeline[-max_events:] if max_events else ()
    rows = [[e.date.isoformat(), EVENT_LABELS.get(e.kind, e.kind), e.count, e.hosts] for e in events]
    lines = ["## Timeline", "", *_table(["Date", "Event", "Findings", "Hosts"], rows, frozenset({2, 3}))]
    if len(cf.timeline) > len(events):
        earlier = len(cf.timeline) - len(events)
        lines += [
            "",
            (
                f"Showing the latest {len(events)} of {len(cf.timeline)} dated events; "
                f"{earlier} earlier events are in the JSON."
            ),
        ]
    return lines


def case_markdown(
    cf: CaseFile,
    max_hosts: int = DEFAULT_MAX_HOSTS,
    max_vulns: int = DEFAULT_MAX_VULNS,
    max_events: int = DEFAULT_MAX_EVENTS,
) -> str:
    sources = (
        f"{plural(len(cf.evidence_ids), 'Tenable finding ID')} support this case; "
        "they are listed in the JSON export (`evidence_ids`)."
    )
    return _assemble(
        [
            _case_header(cf),
            ["## Summary", "", *[f"- {md_text(line)}" for line in cf.facts_summary]],
            _case_score(cf),
            _case_fixes(cf),
            _case_vulnerabilities(cf, max_vulns),
            ["## Affected hosts", "", *_host_section(cf.hosts, max_hosts, csv_hint=False)],
            _case_timeline(cf, max_events),
            ["## Limitations", "", *[f"- {md_text(item)}" for item in cf.limitations]],
            ["## Source records", "", sources],
            [
                "## Disposition",
                "",
                "Not yet recorded. The analyst records a disposition separately; nothing in this file is a verdict.",
            ],
        ]
    )
