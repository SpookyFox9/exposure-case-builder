"""Real fix dates (last_fixed, resurfaced) replace the 'last seen' approximations when present."""

import dataclasses
from datetime import date, datetime, timezone

from test_cluster import finding

from exposure_case.cluster import build_clusters
from exposure_case.timeline import build_timeline


def utc(text):
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc)


def timed(f, first="2026-06-01T00:00:00", last="2026-11-01T00:00:00", **fix):
    return dataclasses.replace(f, first_found=utc(first), last_found=utc(last), **{k: utc(v) if isinstance(v, str) else v for k, v in fix.items()})


def kinds(*records):
    return {(e.kind, e.date) for e in build_timeline(build_clusters(list(records))[0])}


def test_fixed_finding_with_last_fixed_uses_the_real_date():
    got = kinds(finding("a1"), timed(finding("f1", asset="a2", state="FIXED"), last="2026-08-15T00:00:00",
                                      last_fixed="2026-08-16T09:00:00"))
    assert ("fixed", date(2026, 8, 16)) in got
    assert not any(k == "last_seen_fixed" for k, _ in got)


def test_fixed_finding_without_last_fixed_keeps_last_seen_wording():
    got = kinds(finding("a1"), timed(finding("f1", asset="a2", state="FIXED"), last="2026-08-15T00:00:00"))
    assert ("last_seen_fixed", date(2026, 8, 15)) in got


def test_reopened_finding_uses_resurfaced_and_its_earlier_fix():
    got = kinds(timed(finding("f1", state="REOPENED"), last_fixed="2026-07-01T00:00:00", resurfaced="2026-09-27T00:00:00"))
    assert ("fixed", date(2026, 7, 1)) in got and ("reopened", date(2026, 9, 27)) in got
    assert not any(k == "last_seen_reopened" for k, _ in got)


def test_reopened_finding_without_resurfaced_keeps_last_seen_wording():
    got = kinds(timed(finding("f1", state="REOPENED"), last="2026-10-20T00:00:00"))
    assert ("last_seen_reopened", date(2026, 10, 20)) in got


def test_every_finding_still_has_a_first_seen_event_and_order_is_stable():
    recs = [timed(finding("f1", state="REOPENED"), last_fixed="2026-07-01T00:00:00", resurfaced="2026-09-27T00:00:00"),
            timed(finding("f2", asset="a2", state="FIXED"), last_fixed="2026-08-16T00:00:00")]
    tl = build_timeline(build_clusters(recs)[0])
    assert sum(e.count for e in tl if e.kind == "first_seen") == 2
    keys = [(e.date, e.kind) for e in tl]
    assert keys == sorted(keys, key=lambda k: (k[0], ["first_seen", "fixed", "reopened", "last_seen_reopened", "last_seen_fixed"].index(k[1])))
