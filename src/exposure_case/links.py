"""Two-way links between cases (risk view) and fix packages (engineer view).

Every active, non-info finding is in exactly one case and exactly one package, so the links are a
partition of the same findings seen two ways. ``share`` is always a fraction of the *near* side:
for a case, how much of the case a package clears; for a package, how much of it sits in a case.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from .cluster import Cluster
from .fixes import FixPackage


@dataclass(frozen=True)
class Link:
    other_id: str
    title: str
    findings: int
    share: float

    def to_dict(self) -> dict:
        return {"id": self.other_id, "title": self.title, "findings": self.findings, "share": round(self.share, 4)}


@dataclass(frozen=True)
class Links:
    case_to_fixes: dict[str, tuple[Link, ...]]
    fix_to_cases: dict[str, tuple[Link, ...]]

    def fixes_for(self, cluster_id: str) -> tuple[Link, ...]:
        return self.case_to_fixes.get(cluster_id, ())

    def cases_for(self, package_id: str) -> tuple[Link, ...]:
        return self.fix_to_cases.get(package_id, ())


def _sorted_links(counts: Counter[str], total: int, titles: dict[str, str]) -> tuple[Link, ...]:
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return tuple(Link(other, titles[other], n, n / total) for other, n in ordered)


def link_cases_and_fixes(cases: Iterable[Cluster], packages: Iterable[FixPackage]) -> Links:
    """Cross-reference by finding id; raise if the two sides do not describe the same findings."""
    cases, packages = tuple(cases), tuple(packages)
    case_of = {r.finding_id: c.cluster_id for c in cases for r in c.active}
    package_of = {r.finding_id: p.package_id for p in packages for r in p.active}
    if case_of.keys() != package_of.keys():
        stray = sorted(case_of.keys() ^ package_of.keys())[:3]
        raise ValueError(f"findings not in both views, e.g. {stray}")

    case_titles = {c.cluster_id: c.title for c in cases}
    package_titles = {p.package_id: p.title for p in packages}
    pairs = Counter((case_of[f], package_of[f]) for f in case_of)

    per_case: dict[str, Counter[str]] = {}
    per_package: dict[str, Counter[str]] = {}
    for (case_id, package_id), n in pairs.items():
        per_case.setdefault(case_id, Counter())[package_id] += n
        per_package.setdefault(package_id, Counter())[case_id] += n

    return Links(
        case_to_fixes={cid: _sorted_links(cnt, sum(cnt.values()), package_titles) for cid, cnt in per_case.items()},
        fix_to_cases={pid: _sorted_links(cnt, sum(cnt.values()), case_titles) for pid, cnt in per_package.items()},
    )
