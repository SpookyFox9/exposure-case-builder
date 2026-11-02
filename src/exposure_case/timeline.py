"""Per-case timeline built only from the dates the export actually contains.

The export has ``first_found`` and ``last_found`` per finding, not an event log. So the timeline
is honest about that: ``last_seen_fixed`` is the last time a since-fixed finding was observed
(the fix happened after it), and ``last_seen_reopened`` is the latest observation of a finding
that came back, not the moment it reopened.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import date

from .cluster import Cluster
from .ingest import FindingRecord
from .schema import Evidence

KIND_ORDER = ("first_seen", "last_seen_reopened", "last_seen_fixed")


@dataclass(frozen=True)
class TimelineEvent:
    date: date
    kind: str
    hosts: int
    evidence: tuple[Evidence, ...]

    @property
    def count(self) -> int:
        return len(self.evidence)

    def to_dict(self) -> dict:
        return {
            "date": self.date.isoformat(),
            "kind": self.kind,
            "count": self.count,
            "hosts": self.hosts,
            "evidence": [e.to_dict() for e in self.evidence],
        }


def _events(records: list[FindingRecord], kind: str, when) -> list[TimelineEvent]:
    by_day: dict[date, list[FindingRecord]] = defaultdict(list)
    for record in records:
        by_day[when(record).date()].append(record)
    return [
        TimelineEvent(
            date=day,
            kind=kind,
            hosts=len({r.asset_uuid for r in rs}),
            evidence=tuple(r.evidence() for r in sorted(rs, key=lambda r: r.finding_id)),
        )
        for day, rs in by_day.items()
    ]


def build_timeline(cluster: Cluster) -> tuple[TimelineEvent, ...]:
    """Chronological events for a case, grouped per UTC day; ties ordered by KIND_ORDER."""
    everything = list(cluster.active) + list(cluster.fixed)
    events = _events(everything, "first_seen", lambda r: r.first_found)
    events += _events([r for r in cluster.active if r.state == "REOPENED"], "last_seen_reopened", lambda r: r.last_found)
    events += _events(list(cluster.fixed), "last_seen_fixed", lambda r: r.last_found)
    return tuple(sorted(events, key=lambda e: (e.date, KIND_ORDER.index(e.kind))))
