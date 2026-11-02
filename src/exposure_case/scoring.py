"""Transparent, deterministic case scoring. No ML.

Each component is a 0..1 value times its weight; the total is the sum (max 100) and the
per-component breakdown is always returned so a human can see why a case ranks where it does.
VPR/CVSS are deliberately NOT inputs: the workbench plugin list is capped at 5,000 rows, so
coverage is partial (4,049 of 7,677 clusters in the 2026-11-02 export).
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime

from .cluster import Cluster
from .ingest import FindingRecord

# (component, weight). Single source of truth; documented in docs/PLAN.md.
WEIGHTS: tuple[tuple[str, int], ...] = (
    ("severity", 30),     # worst active severity
    ("exploit", 25),      # known exploitation / exploit availability
    ("breadth", 15),      # how many hosts are affected (log scale)
    ("volume", 10),       # how many distinct vulnerabilities the case covers (log scale)
    ("age", 5),           # how long the oldest active finding has been open
    ("unsupported", 5),   # vendor no longer supports the product
    ("recurrence", 5),    # findings that came back after being fixed
    ("patch", 5),         # a patch exists, so the fix is actionable
)
SEVERITY_SCALE = {"critical": 1.0, "high": 0.75, "medium": 0.4, "low": 0.1, "info": 0.0}
EXPLOIT_KEV = 1.0  # on the CISA Known Exploited Vulnerabilities list
EXPLOIT_MALWARE = 1.0
EXPLOIT_VPR_CRITICAL = 0.9  # VPR 9.0-10 (Tenable's critical band)
EXPLOIT_VPR_HIGH = 0.7  # VPR 7.0-8.9 (Tenable's high band)
EXPLOIT_AVAILABLE = 0.6
VPR_CRITICAL_MIN = 9.0
VPR_HIGH_MIN = 7.0
EXPLOIT_IN_NEWS_BONUS = 0.2
VOLUME_SATURATION = 1000  # distinct plugins
AGE_SATURATION_DAYS = 180
RECURRENCE_SATURATION = 5


@dataclass(frozen=True)
class ScoreComponent:
    name: str
    weight: int
    raw: float  # 0..1
    detail: str

    @property
    def points(self) -> float:
        return self.weight * self.raw

    def to_dict(self) -> dict:
        return {"name": self.name, "weight": self.weight, "raw": round(self.raw, 4),
                "points": round(self.points, 2), "detail": self.detail}


@dataclass(frozen=True)
class Score:
    components: tuple[ScoreComponent, ...]

    @property
    def total(self) -> float:
        return sum(c.points for c in self.components)

    def to_dict(self) -> dict:
        return {"total": round(self.total, 2), "components": [c.to_dict() for c in self.components]}


@dataclass(frozen=True)
class RankedCluster:
    rank: int
    cluster: Cluster
    score: Score


def fleet_size(records: Iterable[FindingRecord]) -> int:
    """Distinct assets in the export (any state or severity)."""
    return len({r.asset_uuid for r in records})


def as_of_from(records: Sequence[FindingRecord]) -> datetime:
    """Reference time for ages: the latest observation in the data, never the wall clock."""
    if not records:
        raise ValueError("cannot derive an as-of time from no records")
    return max(r.last_found for r in records)


def _severity(c: Cluster) -> ScoreComponent:
    worst = max(c.active, key=lambda r: SEVERITY_SCALE[r.severity]).severity
    return ScoreComponent("severity", 30, SEVERITY_SCALE[worst], f"worst active severity: {worst}")


def _exploit_signal(r: FindingRecord) -> tuple[float, str]:
    """Strongest exploitation signal on one finding, with the reason."""
    if r.on_cisa_kev:
        return EXPLOIT_KEV, "on the CISA KEV list"
    if r.exploited_by_malware:
        return EXPLOIT_MALWARE, "exploited by malware"
    if r.vpr_score is not None and r.vpr_score >= VPR_CRITICAL_MIN:
        return EXPLOIT_VPR_CRITICAL, f"VPR {r.vpr_score:g} (critical)"
    if r.vpr_score is not None and r.vpr_score >= VPR_HIGH_MIN:
        return EXPLOIT_VPR_HIGH, f"VPR {r.vpr_score:g} (high)"
    if r.exploit_available:
        return EXPLOIT_AVAILABLE, "public exploit available"
    return 0.0, "no known exploit"


def _exploit(c: Cluster) -> ScoreComponent:
    # compare (score, reason) so equal scores resolve by text, not by record order
    raw, why = max(_exploit_signal(r) for r in c.active)
    if any(r.in_the_news for r in c.active):
        raw, why = min(1.0, raw + EXPLOIT_IN_NEWS_BONUS), why + ", in the news"
    return ScoreComponent("exploit", 25, raw, why)


def _breadth(c: Cluster, fleet: int) -> ScoreComponent:
    n = c.asset_count
    denominator = math.log1p(max(fleet, n, 1))
    return ScoreComponent("breadth", 15, min(1.0, math.log1p(n) / denominator), f"{n} of {max(fleet, n)} hosts affected")


def _finding(n: int) -> str:
    return f"{n} finding" if n == 1 else f"{n} findings"


def _volume(c: Cluster) -> ScoreComponent:
    n = len(c.plugin_ids)
    raw = min(1.0, math.log1p(n) / math.log1p(VOLUME_SATURATION))
    return ScoreComponent("volume", 10, raw, f"{n} distinct {'vulnerability' if n == 1 else 'vulnerabilities'}, {_finding(len(c.active))}")


def _age(c: Cluster, as_of: datetime) -> ScoreComponent:
    days = max(0, (as_of - min(r.first_found for r in c.active)).days)
    return ScoreComponent("age", 5, min(1.0, days / AGE_SATURATION_DAYS), f"oldest active finding first seen {days} days ago")


def _unsupported(c: Cluster) -> ScoreComponent:
    n = sum(r.unsupported_by_vendor for r in c.active)
    return ScoreComponent("unsupported", 5, 1.0 if n else 0.0, f"{_finding(n)} on vendor-unsupported software")


def _recurrence(c: Cluster) -> ScoreComponent:
    n = sum(r.state == "REOPENED" for r in c.active)
    return ScoreComponent("recurrence", 5, min(1.0, n / RECURRENCE_SATURATION), f"{_finding(n)} reopened after a fix")


def _patch(c: Cluster) -> ScoreComponent:
    n = sum(r.has_patch for r in c.active)
    return ScoreComponent("patch", 5, 1.0 if n else 0.0, f"{_finding(n)} with a vendor patch available")


def score_cluster(cluster: Cluster, fleet: int, as_of: datetime) -> Score:
    """Score one case. ``fleet`` is the total host count; ``as_of`` anchors ages."""
    built = {
        "severity": _severity(cluster),
        "exploit": _exploit(cluster),
        "breadth": _breadth(cluster, fleet),
        "volume": _volume(cluster),
        "age": _age(cluster, as_of),
        "unsupported": _unsupported(cluster),
        "recurrence": _recurrence(cluster),
        "patch": _patch(cluster),
    }
    return Score(tuple(built[name] for name, _ in WEIGHTS))


def rank_clusters(clusters: Iterable[Cluster], fleet: int, as_of: datetime) -> tuple[RankedCluster, ...]:
    """Rank by total score (desc), ties broken by cluster id so output is deterministic."""
    scored = sorted(
        ((score_cluster(c, fleet, as_of), c) for c in clusters),
        key=lambda pair: (-pair[0].total, pair[1].cluster_id),
    )
    return tuple(RankedCluster(rank=i, cluster=c, score=s) for i, (s, c) in enumerate(scored, start=1))
