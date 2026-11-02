from datetime import date

from test_cluster import finding

from exposure_case.cluster import build_clusters
from exposure_case.ingest import PluginInfo
from exposure_case.reconcile import reconcile
from exposure_case.timeline import build_timeline


def with_times(f, first, last):
    import dataclasses
    from datetime import datetime, timezone

    return dataclasses.replace(
        f,
        first_found=datetime.fromisoformat(first).replace(tzinfo=timezone.utc),
        last_found=datetime.fromisoformat(last).replace(tzinfo=timezone.utc),
    )


def case(*records):
    return build_clusters(list(records))[0]


# --- timeline ---


def test_first_seen_events_are_grouped_per_day_and_sorted():
    c = case(
        with_times(finding("f1", asset="a1"), "2026-06-02T10:00:00", "2026-11-01T00:00:00"),
        with_times(finding("f2", asset="a2"), "2026-06-02T23:00:00", "2026-11-01T00:00:00"),
        with_times(finding("f3", asset="a3"), "2026-06-01T01:00:00", "2026-11-01T00:00:00"),
    )
    events = [e for e in build_timeline(c) if e.kind == "first_seen"]
    assert [(e.date, e.count, e.hosts) for e in events] == [(date(2026, 6, 1), 1, 1), (date(2026, 6, 2), 2, 2)]


def test_every_event_carries_evidence_matching_its_count():
    c = case(with_times(finding("f1"), "2026-06-02T10:00:00", "2026-11-01T00:00:00"))
    for e in build_timeline(c):
        assert e.count == len(e.evidence) > 0
        assert all(ev.source == "finding" for ev in e.evidence)


def test_fixed_and_reopened_events():
    c = case(
        with_times(finding("f1", asset="a1"), "2026-06-01T00:00:00", "2026-11-01T00:00:00"),
        with_times(finding("f2", asset="a2", state="FIXED"), "2026-06-01T00:00:00", "2026-08-15T00:00:00"),
        with_times(finding("f3", asset="a3", state="REOPENED"), "2026-06-01T00:00:00", "2026-10-20T00:00:00"),
    )
    kinds = {(e.kind, e.date) for e in build_timeline(c)}
    assert ("last_seen_fixed", date(2026, 8, 15)) in kinds
    assert ("last_seen_reopened", date(2026, 10, 20)) in kinds
    assert sum(1 for e in build_timeline(c) if e.kind == "first_seen") == 1  # all three first seen same day


def test_timeline_is_chronological_with_stable_kind_order():
    c = case(
        with_times(finding("f1", asset="a1"), "2026-06-01T00:00:00", "2026-11-01T00:00:00"),
        with_times(finding("f2", asset="a2", state="FIXED"), "2026-06-01T00:00:00", "2026-06-01T12:00:00"),
    )
    keys = [(e.date, e.kind) for e in build_timeline(c)]
    assert keys == sorted(keys)


def test_timeline_to_dict():
    c = case(with_times(finding("f1"), "2026-06-02T10:00:00", "2026-11-01T00:00:00"))
    d = build_timeline(c)[0].to_dict()
    assert (
        d["date"] == "2026-06-02"
        and d["kind"] == "first_seen"
        and d["evidence"] == [{"source": "finding", "record_id": "f1"}]
    )


# --- reconciliation ---


def info(pid, count):
    return PluginInfo(plugin_id=pid, count=count, vpr_score=None, cvss_base_score=None, cvss3_base_score=None)


def test_reconcile_counts_exact_matches_and_mismatches():
    recs = [
        finding("f1", plugin=1, asset="a1"),
        finding("f2", plugin=1, asset="a2"),
        finding("f3", plugin=2, asset="a1"),
    ]
    r = reconcile(recs, {1: info(1, 2), 2: info(2, 3)})
    assert (r.compared, r.exact) == (2, 1)
    assert [(m.plugin_id, m.export_assets, m.export_findings, m.workbench_count) for m in r.mismatches] == [
        (2, 1, 1, 3)
    ]


def test_reconcile_accepts_finding_instances_as_a_match():
    # same host, two ports: 1 distinct host but 2 instances; Tenable counts instances
    recs = [finding("f1", plugin=1, asset="a1"), finding("f2", plugin=1, asset="a1")]
    r = reconcile(recs, {1: info(1, 2)})
    assert (r.compared, r.exact, r.instances_only, len(r.mismatches)) == (1, 1, 1, 0)


def test_reconcile_ignores_fixed_and_counts_info_plugins():
    recs = [
        finding("f1", plugin=1, asset="a1"),
        finding("f2", plugin=1, asset="a2", state="FIXED"),
        finding("f3", plugin=9, asset="a1", severity="info"),
    ]
    r = reconcile(recs, {1: info(1, 1), 9: info(9, 1)})
    assert (r.compared, r.exact) == (2, 2)


def test_reconcile_reports_plugins_missing_from_workbench():
    r = reconcile([finding("f1", plugin=1)], {})
    assert (r.compared, r.not_in_workbench) == (0, 1)


def test_reconcile_summary_and_direction():
    recs = [finding("f1", plugin=1, asset="a1")]
    r = reconcile(recs, {1: info(1, 4)})
    assert r.export_below_workbench == 1 and r.export_above_workbench == 0
    d = r.to_dict()
    assert d["compared"] == 1 and d["exact"] == 0 and d["mismatch_count"] == 1
    assert d["largest_gaps"][0]["export_findings"] == 1
