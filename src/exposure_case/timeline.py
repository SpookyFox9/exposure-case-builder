"""Per-case timeline built only from the dates the export actually contains.

The export has ``first_found`` and ``last_found`` per finding, not an event log. So the timeline
is honest about that: ``last_seen_fixed`` is the last time a since-fixed finding was observed
(the fix happened after it), and ``last_seen_reopened`` is the latest observation of a finding
that came back, not the moment it reopened. On the minority of findings that carry Tenable's own
``last_fixed`` / ``resurfaced_date``, those real dates are used instead (``fixed`` / ``reopened``).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime

from .cluster import Cluster
from .ingest import FindingRecord
from .schema import Evidence

KIND_ORDER = ("first_seen", "fixed", "reopened", "last_seen_reopened", "last_seen_fixed")


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


def _plan(record: FindingRecord) -> list[tuple[str, datetime]]:
    """The events one finding contributes, preferring Tenable's real dates over last-seen approximations."""
    plan = [("first_seen", record.first_found)]
    if record.last_fixed:
        plan.append(("fixed", record.last_fixed))
    if record.state == "REOPENED":
        plan.append(("reopened", record.resurfaced) if record.resurfaced else ("last_seen_reopened", record.last_found))
    elif record.state == "FIXED" and not record.last_fixed:
        plan.append(("last_seen_fixed", record.last_found))
    return plan


def build_timeline(cluster: Cluster) -> tuple[TimelineEvent, ...]:
    """Chronological events for a case, grouped per UTC day; ties ordered by KIND_ORDER."""
    buckets: dict[tuple[str, date], list[FindingRecord]] = defaultdict(list)
    for record in list(cluster.active) + list(cluster.fixed):
        for kind, when in _plan(record):
            buckets[(kind, when.date())].append(record)
    events = [
        TimelineEvent(
            date=day,
            kind=kind,
            hosts=len({r.asset_uuid for r in rs}),
            evidence=tuple(r.evidence() for r in sorted(rs, key=lambda r: r.finding_id)),
        )
        for (kind, day), rs in buckets.items()
    ]
    return tuple(sorted(events, key=lambda e: (e.date, KIND_ORDER.index(e.kind))))
