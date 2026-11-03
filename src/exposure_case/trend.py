"""Trend diff: what changed between a previous Tenable pull and the current one.

A single export already records FIXED findings with dates. A second pull adds what one cannot: findings that
appeared, findings that appeared only because coverage grew, findings that vanished with no recorded fix, and
findings that came back. This module is a pure function of two lists of records; the baseline is chosen and
validated elsewhere (``baseline.py``).

Matching: a finding is the same finding when its id *and* ``(asset, plugin, port, protocol)`` agree. The same id
on a different second key is ``id_reuse`` (treated as one finding gone and one new). A different id on the same
second key is a ``possible_rekeys`` count only: it is never merged. Whether Tenable's ids are stable across pulls
is not documented, so these counters exist to make instability visible.

Absence from the later pull is not proof of a fix: the asset may not have been scanned, may have been deleted, or
the scan scope may have changed. ``not_seen_rescanned`` means only that the host has newer observations in the
current export. Informational findings are not counted, but they do count as evidence that a host was scanned,
and a move to or from informational is reported as a severity change. A finding that appears and is already FIXED
is not reported.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime

from .common import SEVERITY_ORDER
from .ingest import FindingRecord

CATEGORIES = (
    "new_since_baseline",
    "newly_visible",
    "fixed_recorded",
    "reopened",
    "not_seen_rescanned",
    "not_seen_not_rescanned",
    "severity_raised",
    "severity_lowered",
    "still_active",
)

_Identity = tuple[str, str, int, int | None, str]  # finding_id, asset, plugin, port, protocol


@dataclass(frozen=True)
class FindingChange:
    """One finding's movement between the two pulls: ids and facts only, no Tenable free text."""

    finding_id: str
    category: str
    asset_uuid: str
    plugin_id: int
    severity_before: str
    severity_after: str
    state_before: str
    state_after: str
    scan_uuid_before: str
    scan_uuid_after: str


@dataclass(frozen=True)
class TrendDiff:
    baseline_as_of: datetime
    current_as_of: datetime
    hosts_baseline: int
    hosts_current: int
    hosts_in_both: int
    hosts_only_baseline: int
    hosts_only_current: int
    changes: tuple[FindingChange, ...]
    id_reuse: int
    possible_rekeys: int

    @property
    def counts(self) -> dict[str, int]:
        """Findings per category, every category present, in the documented order."""
        tally = dict.fromkeys(CATEGORIES, 0)
        for change in self.changes:
            tally[change.category] += 1
        return tally


@dataclass(frozen=True)
class _Context:
    """What the classifiers need to know about the two pulls."""

    baseline_as_of: datetime
    host_before: dict[str, datetime]  # per host, newest observation in the baseline
    seen_now: dict[str, datetime]  # per host, newest observation in the current export


def _identity(r: FindingRecord) -> _Identity:
    return (r.finding_id, r.asset_uuid, r.plugin_id, r.port, r.protocol.upper())


def _index(records: Iterable[FindingRecord]) -> dict[_Identity, FindingRecord]:
    """Every record by identity; informational ones are kept so a re-rating is seen as a re-rating."""
    return {_identity(r): r for r in records}


def _live(r: FindingRecord | None) -> bool:
    """Active and not informational: the findings the counts are about."""
    return r is not None and r.state != "FIXED" and r.severity != "info"


def _latest_seen(records: Iterable[FindingRecord]) -> dict[str, datetime]:
    """Per host, the newest observation of any finding (informational and fixed ones included)."""
    latest: dict[str, datetime] = {}
    for r in records:
        if r.asset_uuid not in latest or r.last_found > latest[r.asset_uuid]:
            latest[r.asset_uuid] = r.last_found
    return latest


def _severity_category(before: FindingRecord, after: FindingRecord) -> str:
    was, now = SEVERITY_ORDER.index(before.severity), SEVERITY_ORDER.index(after.severity)
    if now < was:
        return "severity_raised"
    return "severity_lowered" if now > was else "still_active"


def _came_back(before: FindingRecord, after: FindingRecord, ctx: _Context) -> bool:
    """Active before and active now, but Tenable says it was fixed and came back in between."""
    newly_reopened = after.state == "REOPENED" and before.state != "REOPENED"
    return newly_reopened or (after.resurfaced is not None and after.resurfaced > ctx.baseline_as_of)


def _reclassified(before: FindingRecord, after: FindingRecord) -> str | None:
    """A move to or from informational is a re-rating of the same finding, not an arrival or a disappearance."""
    if _live(before) and after.severity == "info":
        return "severity_lowered"
    if before.severity == "info" and _live(after):
        return "severity_raised"
    return None


def _both(before: FindingRecord, after: FindingRecord, ctx: _Context) -> str | None:
    if before.severity == "info" or after.severity == "info":
        return _reclassified(before, after)
    if _live(before) and _live(after):
        return "reopened" if _came_back(before, after, ctx) else _severity_category(before, after)
    if _live(before):
        return "fixed_recorded"
    return "reopened" if _live(after) else None


def _gone(before: FindingRecord, ctx: _Context) -> str | None:
    """Absent now. 'Rescanned' means the host has observations newer than anything the baseline had for it."""
    if not _live(before):
        return None
    newest_now = ctx.seen_now.get(before.asset_uuid)
    rescanned = newest_now is not None and newest_now > ctx.host_before[before.asset_uuid]
    return "not_seen_rescanned" if rescanned else "not_seen_not_rescanned"


def _appeared(after: FindingRecord, ctx: _Context) -> str | None:
    """New if first seen after the host's own newest baseline observation (the global one for a host the baseline
    never saw); otherwise it was probably there and only became visible."""
    if not _live(after):
        return None
    cutoff = ctx.host_before.get(after.asset_uuid, ctx.baseline_as_of)
    return "new_since_baseline" if after.first_found > cutoff else "newly_visible"


def _classify(before: FindingRecord | None, after: FindingRecord | None, ctx: _Context) -> str | None:
    if before is not None and after is not None:
        return _both(before, after, ctx)
    if before is not None:
        return _gone(before, ctx)
    return _appeared(after, ctx) if after is not None else None


def _change(before: FindingRecord | None, after: FindingRecord | None, category: str) -> FindingChange:
    ref = after if after is not None else before
    if ref is None:
        raise ValueError("a change needs a record from at least one pull")
    return FindingChange(
        finding_id=ref.finding_id,
        category=category,
        asset_uuid=ref.asset_uuid,
        plugin_id=ref.plugin_id,
        severity_before=before.severity if before else "",
        severity_after=after.severity if after else "",
        state_before=before.state if before else "",
        state_after=after.state if after else "",
        scan_uuid_before=before.scan_uuid if before else "",
        scan_uuid_after=after.scan_uuid if after else "",
    )


def _quality(before: dict[_Identity, FindingRecord], after: dict[_Identity, FindingRecord]) -> tuple[int, int]:
    """(id_reuse, possible_rekeys): the signs that finding ids may not be stable between pulls."""
    ids_before = {i[0]: i for i in before}
    id_reuse = sum(1 for i in after if i[0] in ids_before and ids_before[i[0]] != i)
    gone_keys = {i[1:] for i, r in before.items() if i not in after and _live(r)}
    new_keys = {i[1:] for i, r in after.items() if i not in before and _live(r)}
    return id_reuse, len(gone_keys & new_keys)


def diff(baseline: Sequence[FindingRecord], current: Sequence[FindingRecord]) -> TrendDiff:
    """Compare two pulls. Both must be non-empty; the baseline should be the older one."""
    if not baseline or not current:
        raise ValueError("cannot compare an empty pull")
    ctx = _Context(max(r.last_found for r in baseline), _latest_seen(baseline), _latest_seen(current))
    before, after = _index(baseline), _index(current)
    changes = []
    for identity in before.keys() | after.keys():
        b, a = before.get(identity), after.get(identity)
        category = _classify(b, a, ctx)
        if category is not None:
            changes.append(_change(b, a, category))
    changes.sort(key=lambda c: (CATEGORIES.index(c.category), c.finding_id, c.asset_uuid))
    hosts_before, hosts_now = set(ctx.host_before), set(ctx.seen_now)
    id_reuse, rekeys = _quality(before, after)
    return TrendDiff(
        baseline_as_of=ctx.baseline_as_of,
        current_as_of=max(r.last_found for r in current),
        hosts_baseline=len(hosts_before),
        hosts_current=len(hosts_now),
        hosts_in_both=len(hosts_before & hosts_now),
        hosts_only_baseline=len(hosts_before - hosts_now),
        hosts_only_current=len(hosts_now - hosts_before),
        changes=tuple(changes),
        id_reuse=id_reuse,
        possible_rekeys=rekeys,
    )
