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

import hashlib
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from .cluster import Cluster, slugify
from .ingest import FindingRecord
from .schema import Evidence
from .scoring import Score, score_cluster

PATCH_VERBS = frozenset({
    "update", "updates", "updated", "upgrade", "upgrades", "upgraded",
    "apply", "applies", "install", "installs", "patch", "patches",
})
_FILLER_WORDS = frozenset({"please", "note", "also", "you", "should", "then"})
_PATCH_WORD = re.compile(r"\b(update|upgrade|patch)\b")
_CONFIG_WORD = re.compile(r"\b(disable|enable|configure|reconfigure|restrict|filter|remove|block|harden)\b")
_WORKAROUND = re.compile(r"\bworkaround\b")
_MS_RELEASED = re.compile(r"^microsoft has released\b")
_UNESCAPED_COLON = re.compile(r"(?<!\\):")
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _cpe_part(part: str) -> str:
    """One CPE component, or '' for wildcard / not-applicable / empty values."""
    if part in ("", "-", "*") or "?" in part or "*" in part:
        return ""
    return part.replace("\\:", "_").replace("\\", "")


def normalize_product(cpe: str) -> str:
    """``vendor:product`` from a CPE 2.2 (``cpe:/a:v:p:ver``) or 2.3 (``cpe:2.3:a:v:p:...``) string, else ''."""
    text = cpe.strip().lower()
    if text.startswith("cpe:2.3:"):
        parts = _UNESCAPED_COLON.split(text)[3:]
    elif text.startswith("cpe:/"):
        parts = _UNESCAPED_COLON.split(text[len("cpe:/"):])[1:]
    else:
        return ""
    if len(parts) < 2:
        return ""
    vendor, product = _cpe_part(parts[0]), _cpe_part(parts[1])
    return f"{vendor}:{product}" if vendor and product else ""


def _word(token: str) -> str:
    return re.sub(r"[^a-z]", "", token.lower())


def classify_fix(solution: str) -> str:
    """'patch' for update/upgrade/apply/install-style fixes, 'configuration' for the rest, 'unspecified' if empty.

    The opening verb decides (after skipping filler like "Please"). A patch verb followed by a workaround,
    "Microsoft recommends ...", and "Contact the vendor ... to disable X" are all configuration.
    """
    words = solution.split()
    if not words:
        return "unspecified"
    start = 0
    while start < len(words) and _word(words[start]) in _FILLER_WORDS:
        start += 1
    if start == len(words):
        return "configuration"
    first = _word(words[start])
    text = " ".join(words[start:]).lower()
    if first in PATCH_VERBS:
        return "configuration" if _WORKAROUND.search(text) else "patch"
    if first == "microsoft":
        return "patch" if _MS_RELEASED.match(text) else "configuration"
    # "Contact the vendor for an update/patch ..." is a patch; "... to disable X" stays configuration.
    if first == "contact" and _PATCH_WORD.search(text) and not _CONFIG_WORD.search(text):
        return "patch"
    return "configuration"


def _worst(severities: Iterable[str]) -> str:
    present = set(severities)
    return next((s for s in SEVERITY_ORDER if s in present), "info")


@dataclass(frozen=True)
class FixAction:
    """One distinct piece of Tenable solution text and how much applying just that action clears."""

    solution: str
    plugins: int
    findings: int
    hosts: int
    worst_severity: str
    critical_findings: int
    critical_share: float  # fraction of the fleet's active critical findings this action alone clears

    def to_dict(self) -> dict:
        return {"solution": self.solution, "plugins": self.plugins, "findings": self.findings,
                "hosts": self.hosts, "worst_severity": self.worst_severity,
                "critical_findings": self.critical_findings, "critical_share": round(self.critical_share, 4)}


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
    """Totals CONTAINED in this package, summed across ``actions`` distinct fix actions.

    No single action clears all of it unless ``actions`` is 1; per-action figures are on each FixAction.
    """

    actions: int
    plugins: int
    findings: int
    hosts: int
    by_severity: dict[str, int]
    exploitable_findings: int  # public exploit available
    malware_findings: int  # exploited by malware
    kev_findings: int  # on the CISA KEV list
    critical_share: float  # fraction of the fleet's active critical findings contained in this package

    def to_dict(self) -> dict:
        return {"actions": self.actions, "plugins": self.plugins, "findings": self.findings, "hosts": self.hosts,
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


def _group_key(record: FindingRecord) -> tuple[str, str, int]:
    """(product, fix_type, plugin_id or 0): the exact grouping key, never a lossy slug."""
    fix_type = classify_fix(record.solution)
    product = next((p for p in (normalize_product(c) for c in record.cpe) if p), "")
    return product, fix_type, (0 if product else record.plugin_id)


def _package_ids(keys: Iterable[tuple[str, str, int]]) -> dict[tuple[str, str, int], str]:
    """Readable ids; a short hash is added only when two different products share a slug."""
    keys = list(keys)
    products_by_slug: dict[str, set[str]] = defaultdict(set)
    for product, _, _ in keys:
        if product:
            products_by_slug[slugify(product)].add(product)
    ids: dict[tuple[str, str, int], str] = {}
    for product, fix_type, plugin_id in keys:
        if not product:
            ids[(product, fix_type, plugin_id)] = f"fix:plugin-{plugin_id}:{fix_type}"
            continue
        slug = slugify(product)
        if len(products_by_slug[slug]) > 1:
            slug = f"{slug}-{hashlib.sha1(product.encode(), usedforsecurity=False).hexdigest()[:6]}"
        ids[(product, fix_type, plugin_id)] = f"fix:{slug}:{fix_type}"
    return ids


def _actions(members: list[FindingRecord], fleet_critical: int) -> tuple[FixAction, ...]:
    groups: dict[str, list[FindingRecord]] = defaultdict(list)
    for r in members:
        groups[" ".join(r.solution.split()) or "(no solution text provided)"].append(r)
    actions = []
    for text, rs in groups.items():
        critical = sum(r.severity == "critical" for r in rs)
        actions.append(FixAction(
            text, len({r.plugin_id for r in rs}), len(rs), len({r.asset_uuid for r in rs}),
            _worst(r.severity for r in rs), critical, critical / fleet_critical if fleet_critical else 0.0))
    return tuple(sorted(actions, key=lambda a: (-a.plugins, -a.findings, a.solution)))


def _hosts(members: list[FindingRecord]) -> tuple[HostLine, ...]:
    per_host: dict[str, list[FindingRecord]] = defaultdict(list)
    for r in members:
        per_host[r.asset_uuid].append(r)
    lines = []
    for uuid, rs in per_host.items():
        latest = max(rs, key=lambda r: (r.last_found, r.finding_id))  # a renamed host shows today's details
        lines.append(HostLine(uuid, latest.hostname, latest.ipv4,
                              latest.operating_system[0] if latest.operating_system else "",
                              len(rs), len({r.plugin_id for r in rs}), _worst(r.severity for r in rs),
                              min(r.first_found for r in rs)))
    return tuple(sorted(lines, key=lambda h: (SEVERITY_ORDER.index(h.worst_severity), -h.findings, h.asset_uuid)))


def _impact(members: list[FindingRecord], fleet_critical: int, actions: int) -> Impact:
    critical = sum(r.severity == "critical" for r in members)
    return Impact(
        actions=actions,
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
    groups: dict[tuple[str, str, int], list[FindingRecord]] = defaultdict(list)
    for r in usable:
        groups[_group_key(r)].append(r)
    ids = _package_ids(groups)

    packages: list[FixPackage] = []
    for key in sorted(groups, key=lambda k: ids[k]):
        product, fix_type, _ = key
        members = sorted((r for r in groups[key] if r.state != "FIXED"), key=lambda r: r.finding_id)
        if not members:
            continue
        plugin_ids = tuple(sorted({r.plugin_id for r in members}))
        label = product or f"plugin {plugin_ids[0]}"
        actions = _actions(members, fleet_critical)
        packages.append(FixPackage(
            package_id=ids[key], product=product, fix_type=fix_type, title=f"{label} ({fix_type})",
            plugin_ids=plugin_ids, active=tuple(members),
            fixed_findings=sum(r.state == "FIXED" for r in groups[key]),
            actions=actions, hosts=_hosts(members), impact=_impact(members, fleet_critical, len(actions)),
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
