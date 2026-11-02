"""Render cases and fix packages as Markdown, CSV and JSON.

Everything Tenable supplies (solution text, hostnames, advisory URLs) is untrusted: it is neutralized
for Markdown/HTML on the way into Markdown and for spreadsheet formulas on the way into CSV. Output is
deterministic (no wall-clock time). File writes need ``confirm=True`` and go only to the directory given.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Iterable
from pathlib import Path

from .case import SCOPE_NOTE, CaseFile, PackageView
from .cluster import slugify
from .fixes import FixAction, HostLine

DEFAULT_MAX_HOSTS = 25
DEFAULT_MAX_ACTIONS = 15
DEFAULT_MAX_REFS = 25
DEFAULT_MAX_VULNS = 15
DEFAULT_MAX_EVENTS = 40
DEFAULT_MAX_CASES = 10
EVENT_LABELS = {
    "first_seen": "First seen", "fixed": "Fixed", "reopened": "Reopened",
    "last_seen_reopened": "Last seen (reopened)", "last_seen_fixed": "Last seen before fix",
}
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


class ExportError(ValueError):
    """Raised when an export cannot be written."""


# --- neutralizers ---

def md_text(value: object) -> str:
    """Single-line, markup-safe text: no control characters, no HTML, no line breaks."""
    text = _CONTROL.sub("", str(value))
    text = text.replace("<", "\\<").replace(">", "\\>")  # CommonMark backslash escapes: literal, never markup
    return " ".join(text.split())


def md_cell(value: object) -> str:
    """``md_text`` that is also safe inside a Markdown table cell."""
    return md_text(value).replace("|", "\\|").replace("`", "'")


def csv_cell(value: object) -> object:
    """Numbers pass through; strings that a spreadsheet would run as a formula get a leading apostrophe."""
    if not isinstance(value, str):
        return value
    text = _CONTROL.sub("", value) if value[:1] not in ("\t", "\r") else value
    return f"'{text}" if text.startswith(_FORMULA_START) else text


def _csv(header: list[str], rows: Iterable[list[object]]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(header)
    for row in rows:
        writer.writerow([csv_cell(v) for v in row])
    return out.getvalue()


def _json(data: object) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def plural(n: int, word: str, many: str | None = None) -> str:
    return f"{n:,} {word}" if n == 1 else f"{n:,} {many or word + 's'}"


def _pct(share: float) -> str:
    return f"{share * 100:.1f}%"


def _table(header: list[str], rows: list[list[object]], right: frozenset[int] = frozenset()) -> list[str]:
    align = ["---:" if i in right else "---" for i in range(len(header))]
    lines = ["| " + " | ".join(header) + " |", "| " + " | ".join(align) + " |"]
    lines += ["| " + " | ".join(md_cell(c) for c in row) + " |" for row in rows]
    return lines


def _host_rows(hosts: Iterable[HostLine]) -> list[list[object]]:
    return [[h.hostname or h.asset_uuid, h.ipv4, h.operating_system, h.findings, h.worst_severity,
             h.oldest_first_found.date().isoformat()] for h in hosts]


def _host_section(hosts: tuple[HostLine, ...], max_hosts: int, csv_hint: bool = True) -> list[str]:
    lines = _table(["Host", "IP", "OS", "Findings", "Worst severity", "First seen"],
                   _host_rows(hosts[:max_hosts]), frozenset({3}))
    if len(hosts) > max_hosts:
        tail = "the full list is in the CSV" if csv_hint else "the full list is in the JSON"
        lines += ["", f"Showing {max_hosts} of {len(hosts)} hosts; {tail}."]
    return lines


def _capped_list(items: tuple[str, ...], cap: int) -> list[str]:
    lines = [f"- {md_text(i)}" for i in items[:cap]]
    if len(items) > cap:
        lines.append(f"- plus {len(items) - cap} more in the JSON")
    return lines or ["- none recorded"]


# --- engineer handoff ---

def _action_rows(actions: Iterable[FixAction]) -> list[list[object]]:
    return [[a.solution, a.plugins, a.hosts, a.worst_severity,
             _pct(a.critical_share) if a.critical_findings else "\u2013"] for a in actions]


def package_markdown(view: PackageView, max_hosts: int = DEFAULT_MAX_HOSTS, max_actions: int = DEFAULT_MAX_ACTIONS,
                     max_refs: int = DEFAULT_MAX_REFS, max_cases: int = DEFAULT_MAX_CASES) -> str:
    p, imp = view.package, view.package.impact
    sev = ", ".join(f"{k} {v}" for k, v in sorted(imp.by_severity.items(), key=lambda kv: kv[0])) or "none"
    lines = [
        f"# Fix: {md_text(p.title)}", "",
        (f"Package `{md_text(p.package_id)}` · priority #{view.rank} (score {view.score.total:.1f}/100) · "
         f"data as of {view.as_of.date()}"), "",
        "**Why it ranks here:** " + "; ".join(md_text(r) for r in view.priority_reasons) + ".", "",
        "## What to do", "",
        md_text(SCOPE_NOTE), "",
        *_table(["Action (Tenable solution)", "Vulnerabilities", "Hosts", "Worst severity", "Clears this share of fleet criticals"],
                _action_rows(p.actions[:max_actions]), frozenset({1, 2, 4})),
    ]
    if len(p.actions) > max_actions:
        lines += ["", f"plus {len(p.actions) - max_actions} more actions in the CSV and JSON."]
    lines += [
        "", "## Impact (contained in this package)", "",
        (f"- {plural(imp.actions, 'distinct action')}, {plural(imp.plugins, 'vulnerability', 'vulnerabilities')}, "
         f"{plural(imp.findings, 'finding')} on {plural(imp.hosts, 'host')}"),
        f"- Findings by severity: {sev}",
        (f"- Exploitation: {imp.exploitable_findings} with a public exploit, {imp.malware_findings} exploited by "
         f"malware, {imp.kev_findings} on the CISA KEV list"),
        f"- Contains {_pct(imp.critical_share)} of the fleet's critical findings",
        "", "## Affected hosts", "", *_host_section(p.hosts, max_hosts),
        "", "## References", "", "CVEs:", *_capped_list(p.cves, max_refs), "", "Advisories:",
        *_capped_list(p.advisories, max_refs),
        "", "## Cases this relieves", "",
    ]
    lines += [f"- `{md_text(c.other_id)}` {md_text(c.title)}: {plural(c.findings, 'finding')} ({_pct(c.share)} of this package)"
              for c in view.cases[:max_cases]] or ["- none"]
    if len(view.cases) > max_cases:
        lines.append(f"- plus {len(view.cases) - max_cases} more cases in the JSON")
    lines += [
        "", "## Source records", "",
        (f"{plural(len(p.active), 'Tenable finding ID')} support this package; they are listed in the JSON export "
         "(`evidence_ids`)."), "",
        "Hostnames, IP addresses and similar identifiers in this dataset are masked.", "",
    ]
    return "\n".join(lines)


def package_hosts_csv(view: PackageView) -> str:
    header = ["asset_uuid", "hostname", "ipv4", "operating_system", "findings", "plugins", "worst_severity",
              "oldest_first_found"]
    return _csv(header, ([h.asset_uuid, h.hostname, h.ipv4, h.operating_system, h.findings, h.plugins,
                          h.worst_severity, h.oldest_first_found.isoformat()] for h in view.package.hosts))


def package_actions_csv(view: PackageView) -> str:
    header = ["solution", "plugins", "findings", "hosts", "worst_severity", "critical_findings", "critical_share"]
    return _csv(header, ([a.solution, a.plugins, a.findings, a.hosts, a.worst_severity, a.critical_findings,
                          round(a.critical_share, 4)] for a in view.package.actions))


def package_json(view: PackageView) -> str:
    return _json(view.to_dict())


# --- analyst case file ---

def case_markdown(cf: CaseFile, max_hosts: int = DEFAULT_MAX_HOSTS, max_vulns: int = DEFAULT_MAX_VULNS,
                  max_events: int = DEFAULT_MAX_EVENTS) -> str:
    lines = [
        f"# Case: {md_text(cf.title)}", "",
        (f"Case `{md_text(cf.case_id)}` · {md_text(cf.kind)} · rank #{cf.rank} (score {cf.score.total:.1f}/100) · "
         f"data as of {cf.as_of.date()}"), "",
        "## Summary", "", *[f"- {md_text(line)}" for line in cf.facts_summary],
        "", "## Score breakdown", "",
        *_table(["Component", "Points", "Max", "Why"],
                [[c.name, f"{c.points:.1f}", c.weight, c.detail] for c in cf.score.components], frozenset({1, 2})),
        "", "## Fix packages that clear this case", "",
        *(_table(["Package", "Findings", "Share of this case"],
                 [[f"{f.title} ({f.other_id})", f.findings, _pct(f.share)] for f in cf.fixes], frozenset({1, 2}))
          or ["None."]),
        "", "## Top vulnerabilities", "",
        *_table(["Vulnerability", "CVEs", "Severity", "Hosts", "KEV", "VPR", "Tenable fix text"],
                [[v.name, ", ".join(v.cves[:3]), v.severity, v.hosts, "yes" if v.on_cisa_kev else "",
                  "" if v.vpr_score is None else v.vpr_score, v.solution]
                 for v in cf.vulnerabilities[:max_vulns]], frozenset({3})),
    ]
    if len(cf.vulnerabilities) > max_vulns:
        lines += ["", f"Showing {max_vulns} of {len(cf.vulnerabilities)} vulnerabilities; the rest are in the JSON."]
    lines += ["", "## Affected hosts", "", *_host_section(cf.hosts, max_hosts, csv_hint=False), "", "## Timeline", ""]
    events = cf.timeline[:max_events]
    lines += _table(["Date", "Event", "Findings", "Hosts"],
                    [[e.date.isoformat(), EVENT_LABELS.get(e.kind, e.kind), e.count, e.hosts] for e in events],
                    frozenset({2, 3}))
    if len(cf.timeline) > max_events:
        lines += ["", f"Showing the first {max_events} of {len(cf.timeline)} dated events; the rest are in the JSON."]
    lines += [
        "", "## Limitations", "", *[f"- {md_text(item)}" for item in cf.limitations],
        "", "## Source records", "",
        (f"{plural(len(cf.evidence_ids), 'Tenable finding ID')} support this case; they are listed in the JSON export "
         "(`evidence_ids`)."),
        "", "## Disposition", "",
        "Not yet recorded. The analyst records a disposition separately; nothing in this file is a verdict.", "",
    ]
    return "\n".join(lines)


def case_hosts_csv(cf: CaseFile) -> str:
    header = ["asset_uuid", "hostname", "ipv4", "operating_system", "findings", "plugins", "worst_severity",
              "oldest_first_found"]
    return _csv(header, ([h.asset_uuid, h.hostname, h.ipv4, h.operating_system, h.findings, h.plugins,
                          h.worst_severity, h.oldest_first_found.isoformat()] for h in cf.hosts))


def case_json(cf: CaseFile) -> str:
    return _json(cf.to_dict())


# --- writing ---

def _write_all(files: dict[str, str], out_dir: Path, confirm: bool) -> tuple[Path, ...]:
    if confirm is not True:
        raise ExportError("writing export files requires confirm=true")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    root = out_dir.resolve()
    written = []
    for name, content in files.items():
        target = (root / name).resolve()
        if target.parent != root:
            raise ExportError(f"refusing to write outside the export directory: {name}")
        with open(target, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        written.append(target)
    return tuple(written)


def write_package_export(view: PackageView, out_dir: Path, confirm: bool = False) -> tuple[Path, ...]:
    stem = slugify(view.package.package_id) or "package"
    return _write_all({
        f"{stem}.md": package_markdown(view), f"{stem}.json": package_json(view),
        f"{stem}-hosts.csv": package_hosts_csv(view), f"{stem}-actions.csv": package_actions_csv(view),
    }, out_dir, confirm)


def write_case_export(cf: CaseFile, out_dir: Path, confirm: bool = False) -> tuple[Path, ...]:
    stem = slugify(cf.case_id) or "case"
    return _write_all({
        f"{stem}.md": case_markdown(cf), f"{stem}.json": case_json(cf), f"{stem}-hosts.csv": case_hosts_csv(cf),
    }, out_dir, confirm)
