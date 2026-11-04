"""Case files (analyst view) and package views (engineer view).

Both are plain, deterministic data built from the engine's own results: no wall-clock time, no
narrative. Claude writes the narrative later, citing the finding IDs listed here; the human analyst
records the disposition. Nothing in these structures is a verdict.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime

from .common import SEVERITY_ORDER, plural, worst_severity
from .coverage import CoverageStep
from .fixes import FixPackage, HostLine, RankedPackage, classify_fix, host_lines
from .ingest import FindingRecord
from .links import Link, Links
from .scoring import RankedCluster, Score
from .timeline import TimelineEvent, build_timeline

SCOPE_NOTE = (
    "Fix text is Tenable-provided. Tenable's data does not state that one update supersedes another, so each "
    "action is listed separately, and the totals are contained in the package, not cleared by a single action."
)
LIMITATIONS = (
    "Hostnames, IP addresses and similar identifiers in this tenant are masked and are treated as opaque identifiers.",
    (
        "Scores and counts are computed from Tenable export records, and every finding ID is listed. This is evidence "
        "for prioritization and is not a verdict on any person or team."
    ),
    (
        "Timeline dates come from Tenable's first-found and last-found dates and, where present, its fixed and "
        "resurfaced dates."
    ),
    "Fix actions are Tenable's own solution text; Tenable's data does not state that one update replaces another.",
)
MAX_CVES_PER_VULN = 5


@dataclass(frozen=True)
class VulnLine:
    """One vulnerability (plugin) inside a case, with the fix text Tenable gives for it."""

    plugin_id: int
    name: str
    severity: str
    hosts: int
    findings: int
    cves: tuple[str, ...]
    on_cisa_kev: bool
    vpr_score: float | None
    exploit_available: bool
    fix_type: str
    solution: str
    epss_score: float | None = None  # Tenable's EPSS, a percentage; shown beside KEV and VPR, never scored

    def to_dict(self) -> dict:
        return {
            "plugin_id": self.plugin_id,
            "name": self.name,
            "severity": self.severity,
            "hosts": self.hosts,
            "findings": self.findings,
            "cves": list(self.cves),
            "on_cisa_kev": self.on_cisa_kev,
            "vpr_score": self.vpr_score,
            "epss_score": self.epss_score,
            "exploit_available": self.exploit_available,
            "fix_type": self.fix_type,
            "solution": self.solution,
        }


def vulnerability_lines(members: list[FindingRecord]) -> tuple[VulnLine, ...]:
    """One line per plugin, worst first: severity, KEV, VPR, then reach."""
    by_plugin: dict[int, list[FindingRecord]] = defaultdict(list)
    for r in members:
        by_plugin[r.plugin_id].append(r)
    lines = []
    for plugin_id, rs in by_plugin.items():
        rep = min(rs, key=lambda r: r.finding_id)
        vprs = [r.vpr_score for r in rs if r.vpr_score is not None]
        epss = [r.epss_score for r in rs if r.epss_score is not None]
        lines.append(
            VulnLine(
                plugin_id=plugin_id,
                name=rep.plugin_name,
                severity=min((r.severity for r in rs), key=SEVERITY_ORDER.index),
                hosts=len({r.asset_uuid for r in rs}),
                findings=len(rs),
                cves=tuple(sorted({c for r in rs for c in r.cves}))[:MAX_CVES_PER_VULN],
                on_cisa_kev=any(r.on_cisa_kev for r in rs),
                vpr_score=max(vprs) if vprs else None,
                exploit_available=any(r.exploit_available for r in rs),
                fix_type=classify_fix(rep.solution),
                solution=" ".join(rep.solution.split()),
                epss_score=max(epss) if epss else None,
            )
        )
    return tuple(
        sorted(
            lines,
            key=lambda v: (
                SEVERITY_ORDER.index(v.severity),
                not v.on_cisa_kev,
                -(v.vpr_score if v.vpr_score is not None else -1.0),
                -v.hosts,
                v.plugin_id,
            ),
        )
    )


def case_facts(members: list[FindingRecord], as_of: datetime) -> dict:
    oldest = min(r.first_found for r in members)
    return {
        "hosts": len({r.asset_uuid for r in members}),
        "findings": len(members),
        "vulnerabilities": len({r.plugin_id for r in members}),
        "by_severity": dict(Counter(r.severity for r in members)),
        "exploitable_findings": sum(r.exploit_available for r in members),
        "malware_findings": sum(r.exploited_by_malware for r in members),
        "kev_findings": sum(r.on_cisa_kev for r in members),
        "reopened_findings": sum(r.state == "REOPENED" for r in members),
        "oldest_first_found": oldest.isoformat(),
        "age_days": max(0, (as_of - oldest).days),
    }


def facts_summary(facts: dict, as_of: datetime) -> tuple[str, ...]:
    """Plain, checkable statements; every number comes straight from ``facts``."""
    worst = worst_severity(sev for sev, count in facts["by_severity"].items() if count)
    lines = [
        (
            f"{plural(facts['hosts'], 'host')}, {plural(facts['findings'], 'finding')} across "
            f"{plural(facts['vulnerabilities'], 'vulnerability', 'vulnerabilities')}."
        ),
        f"Worst severity: {worst}.",
    ]
    for key, text in (
        ("kev_findings", "on the CISA KEV list"),
        ("malware_findings", "exploited by malware"),
        ("exploitable_findings", "with a public exploit available"),
        ("reopened_findings", "reopened after being fixed"),
    ):
        if facts[key]:
            lines.append(f"{plural(facts[key], 'finding')} {text}.")
    age = plural(facts["age_days"], "day")
    lines.append(f"The oldest finding was first seen {age} before the data snapshot ({as_of.date()}).")
    return tuple(lines)


@dataclass(frozen=True)
class CaseFile:
    case_id: str
    title: str
    kind: str
    rank: int
    score: Score
    facts: dict
    facts_summary: tuple[str, ...]
    fixes: tuple[Link, ...]
    hosts: tuple[HostLine, ...]
    vulnerabilities: tuple[VulnLine, ...]
    timeline: tuple[TimelineEvent, ...]
    evidence_ids: tuple[str, ...]
    limitations: tuple[str, ...]
    as_of: datetime
    disposition: dict | None = None  # filled only by record_disposition, never by the engine

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "kind": self.kind,
            "rank": self.rank,
            "score": self.score.to_dict(),
            "facts": self.facts,
            "facts_summary": list(self.facts_summary),
            "fixes": [f.to_dict() for f in self.fixes],
            "hosts": [h.to_dict() for h in self.hosts],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "timeline": [e.to_dict() for e in self.timeline],
            "evidence_ids": list(self.evidence_ids),
            "limitations": list(self.limitations),
            "as_of": self.as_of.isoformat(),
            "disposition": self.disposition,
        }


def build_case_file(ranked: RankedCluster, links: Links, as_of: datetime) -> CaseFile:
    if as_of.tzinfo is None:
        raise ValueError("as_of must be timezone-aware (finding dates are UTC)")
    case = ranked.cluster
    members = list(case.active)
    facts = case_facts(members, as_of)
    return CaseFile(
        case_id=case.cluster_id,
        title=case.title,
        kind=case.kind,
        rank=ranked.rank,
        score=ranked.score,
        facts=facts,
        facts_summary=facts_summary(facts, as_of),
        fixes=links.fixes_for(case.cluster_id),
        hosts=host_lines(members),
        vulnerabilities=vulnerability_lines(members),
        timeline=build_timeline(case),
        evidence_ids=tuple(e.record_id for e in case.evidence()),
        limitations=LIMITATIONS,
        as_of=as_of,
    )


def priority_reasons(score: Score, top: int = 3) -> tuple[str, ...]:
    best = sorted((c for c in score.components if c.points > 0), key=lambda c: (-c.points, c.name))[:top]
    return tuple(f"{c.detail} ({c.points:.0f} of {c.weight} points for {c.name})" for c in best)


@dataclass(frozen=True)
class PackageView:
    """What an engineer receives: one fix package with its priority and the cases it relieves."""

    rank: int
    score: Score
    package: FixPackage
    cases: tuple[Link, ...]
    priority_reasons: tuple[str, ...]
    as_of: datetime
    coverage: CoverageStep | None = None  # this package's place in the coverage order, if it has urgent findings

    def to_dict(self, max_hosts: int | None = None) -> dict:
        return {
            "rank": self.rank,
            "score": self.score.to_dict(),
            "package": self.package.to_dict(max_hosts),
            "cases": [c.to_dict() for c in self.cases],
            "coverage": self.coverage.to_dict() if self.coverage else None,
            "priority_reasons": list(self.priority_reasons),
            "scope_note": SCOPE_NOTE,
            "limitations": list(LIMITATIONS),
            "evidence_ids": [e.record_id for e in self.package.evidence()],
            "as_of": self.as_of.isoformat(),
        }


def build_package_view(
    ranked: RankedPackage, links: Links, as_of: datetime, coverage: CoverageStep | None = None
) -> PackageView:
    return PackageView(
        rank=ranked.rank,
        score=ranked.score,
        package=ranked.package,
        cases=links.cases_for(ranked.package.package_id),
        priority_reasons=priority_reasons(ranked.score),
        as_of=as_of,
        coverage=coverage,
    )
