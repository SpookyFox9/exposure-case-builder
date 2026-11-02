"""Fix packages: the engineer-facing view, organized around how findings get fixed.

A fix package is one product plus one kind of fix ("apply updates to OpenSSH", "reconfigure OpenSSH").
Every active, non-info finding belongs to exactly one package. Cases (cluster.py) answer "what is risky";
packages answer "what do I do, and what does it clear". Fix text is Tenable's own ``solution`` field and is
always presented as such; nothing here invents remediation steps.

Grouping key: the first CPE's ``vendor:product`` (``/a:`` and ``/o:`` aliases merged) plus a fix type taken
from the opening verb of the solution. ``has_patch`` is NOT used: it is true for 98% of plugins in the
2026-11-02 export, including "Disable J-Web" advisories. Plugins without a CPE become their own package.

Tenable's data does not say that a newer Windows cumulative update replaces older KBs, so packages list each
distinct action as given and never claim one update covers another.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from .cluster import Cluster, slugify
from .ingest import FindingRecord
from .schema import Evidence
from .scoring import Score, score_cluster

PATCH_VERBS = frozenset({"update", "upgrade", "apply", "install", "microsoft"})
_PATCH_WORD = re.compile(r"\b(update|upgrade|patch)\b")
_CONFIG_WORD = re.compile(r"\b(disable|enable|configure|reconfigure|restrict|filter|remove|block|harden)\b")
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def normalize_product(cpe: str) -> str:
    """``vendor:product`` from a CPE 2.2 (``cpe:/a:v:p:ver``) or 2.3 (``cpe:2.3:a:v:p:...``) string, else ''."""
    text = cpe.strip().lower()
    if text.startswith("cpe:2.3:"):
        parts = text.split(":")[3:]
    elif text.startswith("cpe:/"):
        parts = text[len("cpe:/"):].split(":")[1:]
    else:
        return ""
    if len(parts) < 2 or not parts[0] or not parts[1] or "*" in parts[:2]:
        return ""
    return f"{parts[0]}:{parts[1]}"


def classify_fix(solution: str) -> str:
    """'patch' for update/upgrade/apply/install-style fixes, 'configuration' for the rest, 'unspecified' if empty."""
    words = solution.split()
    if not words:
        return "unspecified"
    first = re.sub(r"[^a-z]", "", words[0].lower())
    if first in PATCH_VERBS:
        return "patch"
    text = solution.lower()
    # "Contact the vendor for an update/patch ..." is a patch; "... to disable X" stays configuration.
    if first == "contact" and _PATCH_WORD.search(text) and not _CONFIG_WORD.search(text):
        return "patch"
    return "configuration"


def _worst(severities: Iterable[str]) -> str:
    present = set(severities)
    return next((s for s in SEVERITY_ORDER if s in present), "info")


@dataclass(frozen=True)
class FixAction:
    """One distinct piece of Tenable solution text and how much it clears."""

    solution: str
    plugins: int
    findings: int
    hosts: int
    worst_severity: str

    def to_dict(self) -> dict:
        return {"solution": self.solution, "plugins": self.plugins, "findings": self.findings,
                "hosts": self.hosts, "worst_severity": self.worst_severity}


@dataclass(frozen=True)
class HostLine:
    asset_uuid: str
    hostname: str
    ipv4: str
    operating_system: str
    findings: int
    plugins: int
    worst_severity: str
    oldest_first_found: datetime

    def to_dict(self) -> dict:
        return {"asset_uuid": self.asset_uuid, "hostname": self.hostname, "ipv4": self.ipv4,
                "operating_system": self.operating_system, "findings": self.findings, "plugins": self.plugins,
                "worst_severity": self.worst_severity, "oldest_first_found": self.oldest_first_found.isoformat()}


@dataclass(frozen=True)
class Impact:
    """What applying this package clears."""

    plugins: int
    findings: int
    hosts: int
    by_severity: dict[str, int]
    exploitable_findings: int  # public exploit available
    malware_findings: int  # exploited by malware
    kev_findings: int  # on the CISA KEV list
    critical_share: float  # fraction of the fleet's active critical findings this clears

    def to_dict(self) -> dict:
        return {"plugins": self.plugins, "findings": self.findings, "hosts": self.hosts,
                "by_severity": dict(self.by_severity), "exploitable_findings": self.exploitable_findings,
                "malware_findings": self.malware_findings, "kev_findings": self.kev_findings,
                "critical_share": round(self.critical_share, 4)}


@dataclass(frozen=True)
class FixPackage:
    package_id: str
    product: str
    fix_type: str
    title: str
    plugin_ids: tuple[int, ...]
    active: tuple[FindingRecord, ...]
    fixed_findings: int
    actions: tuple[FixAction, ...]
    hosts: tuple[HostLine, ...]
    impact: Impact
    cves: tuple[str, ...]
    advisories: tuple[str, ...]

    def evidence(self) -> tuple[Evidence, ...]:
        return tuple(r.evidence() for r in sorted(self.active, key=lambda r: r.finding_id))

    def to_dict(self, max_hosts: int | None = None) -> dict:
        hosts = self.hosts if max_hosts is None else self.hosts[:max_hosts]
        return {
            "package_id": self.package_id, "product": self.product, "fix_type": self.fix_type, "title": self.title,
            "plugin_ids": list(self.plugin_ids), "impact": self.impact.to_dict(),
            "actions": [a.to_dict() for a in self.actions], "hosts": [h.to_dict() for h in hosts],
            "hosts_total": len(self.hosts), "fixed_findings": self.fixed_findings,
            "cves": list(self.cves), "advisories": list(self.advisories), "evidence_count": len(self.active),
        }


def _package_key(record: FindingRecord) -> tuple[str, str, str]:
    """(package_id, product, fix_type) for a record."""
    fix_type = classify_fix(record.solution)
    product = next((p for p in (normalize_product(c) for c in record.cpe) if p), "")
    if product:
        return f"fix:{slugify(product)}:{fix_type}", product, fix_type
    return f"fix:plugin-{record.plugin_id}:{fix_type}", "", fix_type


def _actions(members: list[FindingRecord]) -> tuple[FixAction, ...]:
    groups: dict[str, list[FindingRecord]] = defaultdict(list)
    for r in members:
        groups[" ".join(r.solution.split()) or "(no solution text provided)"].append(r)
    actions = [
        FixAction(text, len({r.plugin_id for r in rs}), len(rs), len({r.asset_uuid for r in rs}),
                  _worst(r.severity for r in rs))
        for text, rs in groups.items()
    ]
    return tuple(sorted(actions, key=lambda a: (-a.plugins, -a.findings, a.solution)))


def _hosts(members: list[FindingRecord]) -> tuple[HostLine, ...]:
    per_host: dict[str, list[FindingRecord]] = defaultdict(list)
    for r in members:
        per_host[r.asset_uuid].append(r)
    lines = []
    for uuid, rs in per_host.items():
        first = min(rs, key=lambda r: r.first_found)
        lines.append(HostLine(uuid, first.hostname, first.ipv4, first.operating_system[0] if first.operating_system else "",
                              len(rs), len({r.plugin_id for r in rs}), _worst(r.severity for r in rs),
                              first.first_found))
    return tuple(sorted(lines, key=lambda h: (SEVERITY_ORDER.index(h.worst_severity), -h.findings, h.asset_uuid)))


def _impact(members: list[FindingRecord], fleet_critical: int) -> Impact:
    critical = sum(r.severity == "critical" for r in members)
    return Impact(
        plugins=len({r.plugin_id for r in members}),
        findings=len(members),
        hosts=len({r.asset_uuid for r in members}),
        by_severity=dict(Counter(r.severity for r in members)),
        exploitable_findings=sum(r.exploit_available for r in members),
        malware_findings=sum(r.exploited_by_malware for r in members),
        kev_findings=sum(r.on_cisa_kev for r in members),
        critical_share=critical / fleet_critical if fleet_critical else 0.0,
    )


def build_fix_packages(records: Iterable[FindingRecord]) -> tuple[FixPackage, ...]:
    """Partition every active, non-info finding into fix packages; sorted by package id."""
    usable = [r for r in records if r.severity != "info"]
    fleet_critical = sum(r.state != "FIXED" and r.severity == "critical" for r in usable)
    groups: dict[str, list[FindingRecord]] = defaultdict(list)
    meta: dict[str, tuple[str, str]] = {}
    for r in usable:
        package_id, product, fix_type = _package_key(r)
        groups[package_id].append(r)
        meta.setdefault(package_id, (product, fix_type))

    packages: list[FixPackage] = []
    for package_id in sorted(groups):
        members = sorted((r for r in groups[package_id] if r.state != "FIXED"), key=lambda r: r.finding_id)
        if not members:
            continue
        product, fix_type = meta[package_id]
        plugin_ids = tuple(sorted({r.plugin_id for r in members}))
        label = product or f"plugin {plugin_ids[0]}"
        packages.append(FixPackage(
            package_id=package_id, product=product, fix_type=fix_type, title=f"{label} ({fix_type})",
            plugin_ids=plugin_ids, active=tuple(members),
            fixed_findings=sum(r.state == "FIXED" for r in groups[package_id]),
            actions=_actions(members), hosts=_hosts(members), impact=_impact(members, fleet_critical),
            cves=tuple(sorted({c for r in members for c in r.cves})),
            advisories=tuple(sorted({u for r in members for u in r.see_also})),
        ))
    return tuple(packages)


def as_cluster(package: FixPackage) -> Cluster:
    """View a package as a Cluster so the approved scoring weights apply to it unchanged."""
    return Cluster(
        cluster_id=package.package_id, kind="fix", title=package.title,
        family="", plugin_ids=package.plugin_ids, active=package.active, fixed=(),
    )


@dataclass(frozen=True)
class RankedPackage:
    rank: int
    package: FixPackage
    score: Score


def rank_packages(packages: Iterable[FixPackage], fleet: int, as_of: datetime) -> tuple[RankedPackage, ...]:
    """Rank packages by the same score as cases, ties broken by package id."""
    scored = sorted(
        ((score_cluster(as_cluster(p), fleet, as_of), p) for p in packages),
        key=lambda pair: (-pair[0].total, pair[1].package_id),
    )
    return tuple(RankedPackage(rank=i, package=p, score=s) for i, (s, p) in enumerate(scored, start=1))
