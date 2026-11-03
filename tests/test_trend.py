import dataclasses
import random

import pytest
from test_ingest import raw_record

from exposure_case.ingest import parse_record
from exposure_case.trend import CATEGORIES, TrendDiff, diff

BASE_DAY = "2026-10-01"
NOW_DAY = "2026-11-01"


def rec(
    fid, asset="a1", plugin=1, port=445, severity="high", state="OPEN", first="2026-05-01", last=BASE_DAY, scan="s-1"
):
    raw = raw_record(
        finding_id=fid,
        state=state,
        severity=severity,
        first_found=f"{first}T00:00:00Z",
        last_found=f"{last}T00:00:00Z",
    )
    raw["asset"]["uuid"] = asset
    raw["plugin"]["id"] = plugin
    raw["port"]["port"] = port
    raw["scan"]["uuid"] = scan
    return parse_record(raw)


def now(fid, **kw):
    kw.setdefault("last", NOW_DAY)
    kw.setdefault("scan", "s-2")
    return rec(fid, **kw)


def by_id(result: TrendDiff):
    return {c.finding_id: c for c in result.changes}


def category_of(before, after, fid):
    return by_id(diff(before, after))[fid].category


def test_identical_pulls_are_all_still_active_with_zero_elsewhere():
    pull = [rec("f1"), rec("f2", asset="a2", plugin=2)]
    result = diff(pull, pull)
    assert result.counts["still_active"] == 2
    assert sum(n for k, n in result.counts.items() if k != "still_active") == 0
    assert (result.id_reuse, result.possible_rekeys) == (0, 0)


def test_a_finding_first_seen_after_the_baseline_is_new():
    before = [rec("f1")]
    after = [now("f1"), now("f9", plugin=9, first="2026-10-20")]
    assert category_of(before, after, "f9") == "new_since_baseline"


def test_a_finding_absent_before_but_older_than_the_baseline_is_newly_visible_not_new():
    before = [rec("f1")]
    after = [now("f1"), now("f9", plugin=9, first="2026-06-01")]
    assert category_of(before, after, "f9") == "newly_visible"


def test_open_to_fixed_is_fixed_recorded():
    assert category_of([rec("f1")], [now("f1", state="FIXED")], "f1") == "fixed_recorded"


@pytest.mark.parametrize("state", ["OPEN", "REOPENED"])
def test_fixed_to_active_is_reopened(state):
    assert category_of([rec("f1", state="FIXED")], [now("f1", state=state)], "f1") == "reopened"


def test_findings_that_were_never_active_in_either_pull_are_ignored():
    before = [rec("f1", state="FIXED"), rec("f2", asset="a2", plugin=2, state="FIXED"), rec("f3", asset="a3", plugin=3)]
    after = [now("f1", state="FIXED"), now("f3", asset="a3", plugin=3), now("f4", asset="a4", plugin=4, state="FIXED")]
    assert set(by_id(diff(before, after))) == {"f3"}


def test_absent_on_a_host_that_was_scanned_again_is_not_seen_rescanned():
    before = [rec("f1"), rec("f2", plugin=2)]
    after = [now("f2", plugin=2)]  # same host, newer last_found, f1 is gone
    assert category_of(before, after, "f1") == "not_seen_rescanned"


def test_absent_on_a_host_missing_from_the_new_pull_is_not_seen_not_rescanned():
    before = [rec("f1", asset="a1"), rec("f2", asset="a2", plugin=2)]
    after = [now("f2", asset="a2", plugin=2)]
    assert category_of(before, after, "f1") == "not_seen_not_rescanned"


def test_absent_on_a_host_present_but_not_scanned_since_is_not_seen_not_rescanned():
    before = [rec("f1"), rec("f2", plugin=2)]
    after = [rec("f2", plugin=2)]  # last_found unchanged: no sign the host was scanned again
    assert category_of(before, after, "f1") == "not_seen_not_rescanned"


def test_info_findings_are_not_counted_but_do_show_the_host_was_scanned_again():
    before = [rec("f1")]
    after = [now("i1", plugin=99, severity="info")]
    result = diff(before, after)
    assert set(by_id(result)) == {"f1"} and by_id(result)["f1"].category == "not_seen_rescanned"


@pytest.mark.parametrize(
    "was,is_now,expected",
    [
        ("high", "critical", "severity_raised"),
        ("critical", "medium", "severity_lowered"),
        ("high", "high", "still_active"),
    ],
)
def test_severity_changes_on_a_finding_present_in_both(was, is_now, expected):
    assert category_of([rec("f1", severity=was)], [now("f1", severity=is_now)], "f1") == expected


def test_a_reused_finding_id_on_a_different_asset_is_gone_plus_new_and_counted():
    before = [rec("f1", asset="a1")]
    after = [now("f1", asset="a2", first="2026-10-25")]
    result = diff(before, after)
    assert result.id_reuse == 1
    cats = sorted(c.category for c in result.changes)
    assert cats == ["new_since_baseline", "not_seen_not_rescanned"]


def test_a_new_id_on_the_same_asset_plugin_and_port_is_a_possible_rekey_and_never_merged():
    before = [rec("old")]
    after = [now("new", first="2026-05-01")]
    result = diff(before, after)
    assert result.possible_rekeys == 1 and result.id_reuse == 0
    assert {c.finding_id for c in result.changes} == {"old", "new"}


def test_counts_cover_every_category_and_add_up_to_the_changes():
    before = [rec("f1"), rec("f2", plugin=2), rec("f3", plugin=3, state="FIXED")]
    after = [now("f1", state="FIXED"), now("f3", plugin=3), now("f9", plugin=9, first="2026-10-25")]
    result = diff(before, after)
    assert tuple(result.counts) == CATEGORIES
    assert sum(result.counts.values()) == len(result.changes)


def test_rows_carry_the_finding_id_and_both_scan_uuids():
    change = by_id(diff([rec("f1", scan="s-old")], [now("f1", scan="s-new")]))["f1"]
    assert (change.scan_uuid_before, change.scan_uuid_after) == ("s-old", "s-new")
    gone = by_id(diff([rec("f1", scan="s-old")], [now("f2", plugin=2)]))["f1"]
    assert (gone.scan_uuid_before, gone.scan_uuid_after) == ("s-old", "")


def test_host_overlap_is_reported():
    before = [rec("f1", asset="a1"), rec("f2", asset="a2", plugin=2)]
    after = [now("f1", asset="a1"), now("f3", asset="a3", plugin=3)]
    result = diff(before, after)
    assert (result.hosts_baseline, result.hosts_current, result.hosts_in_both) == (2, 2, 1)
    assert (result.hosts_only_baseline, result.hosts_only_current) == (1, 1)


def test_the_as_of_dates_come_from_the_data_not_the_clock():
    result = diff([rec("f1")], [now("f1")])
    assert (result.baseline_as_of.date().isoformat(), result.current_as_of.date().isoformat()) == (BASE_DAY, NOW_DAY)


def test_input_order_does_not_change_the_result():
    before = [rec(f"f{i}", asset=f"a{i % 3}", plugin=i) for i in range(8)]
    after = [now(f"f{i}", asset=f"a{i % 3}", plugin=i, state="FIXED" if i % 4 == 0 else "OPEN") for i in range(2, 10)]
    expected = diff(before, after)
    for seed in range(5):
        b, a = before[:], after[:]
        random.Random(seed).shuffle(b)
        random.Random(seed + 1).shuffle(a)
        assert diff(b, a) == expected


@pytest.mark.parametrize("empty_side", ["before", "after"])
def test_an_empty_pull_is_a_value_error(empty_side):
    pull = [rec("f1")]
    args = ([], pull) if empty_side == "before" else (pull, [])
    with pytest.raises(ValueError, match="empty"):
        diff(*args)


def test_results_are_frozen():
    result = diff([rec("f1")], [now("f1")])
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.id_reuse = 5  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.changes[0].category = "x"  # type: ignore[misc]


def test_inputs_are_not_modified():
    before, after = [rec("f1")], [now("f1", state="FIXED")]
    snapshot = (list(before), list(after))
    diff(before, after)
    assert (before, after) == snapshot


def test_a_change_with_no_record_on_either_side_is_rejected():
    from exposure_case.trend import _change

    with pytest.raises(ValueError, match="at least one pull"):
        _change(None, None, "still_active")


# --- review fixes: a state change must never hide in a quieter category ---


def test_open_to_reopened_is_reopened_not_still_active():
    assert category_of([rec("f1")], [now("f1", state="REOPENED")], "f1") == "reopened"


def test_a_finding_that_resurfaced_since_the_baseline_is_reopened():
    from datetime import datetime, timezone

    resurfaced = dataclasses.replace(now("f1"), resurfaced=datetime(2026, 10, 15, tzinfo=timezone.utc))
    assert category_of([rec("f1")], [resurfaced], "f1") == "reopened"


def test_reopened_on_both_sides_is_still_active():
    assert category_of([rec("f1", state="REOPENED")], [now("f1", state="REOPENED")], "f1") == "still_active"


def test_a_downgrade_to_info_is_severity_lowered_not_a_disappearance():
    assert category_of([rec("f1", severity="high")], [now("f1", severity="info")], "f1") == "severity_lowered"


def test_an_upgrade_from_info_is_severity_raised_not_new():
    assert category_of([rec("f1", severity="info")], [now("f1", severity="high")], "f1") == "severity_raised"


def test_info_on_both_sides_is_ignored():
    before, after = [rec("f1", severity="info"), rec("k", plugin=2)], [now("f1", severity="info"), now("k", plugin=2)]
    assert "f1" not in by_id(diff(before, after))


def test_new_versus_newly_visible_uses_the_hosts_own_baseline_time():
    # a1 was last seen on Oct 1 and a2 on Oct 10. A finding on a1 first seen Oct 5 is new for a1 even though the
    # whole baseline runs to Oct 10.
    before = [rec("f1", asset="a1", last="2026-10-01"), rec("f2", asset="a2", plugin=2, last="2026-10-10")]
    after = [
        now("f1", asset="a1"),
        now("f2", asset="a2", plugin=2),
        now("f9", asset="a1", plugin=9, first="2026-10-05"),
    ]
    assert category_of(before, after, "f9") == "new_since_baseline"


def test_a_stale_baseline_finding_does_not_make_an_unscanned_host_look_rescanned():
    # f1 was last seen Sep 1 but the host's baseline newest observation is Oct 1; the current export shows
    # nothing newer than Oct 1 for the host, so there is no sign it was scanned again.
    before = [rec("f1", last="2026-09-01"), rec("f2", plugin=2, last="2026-10-01")]
    after = [rec("f2", plugin=2, last="2026-10-01")]
    assert category_of(before, after, "f1") == "not_seen_not_rescanned"


def test_protocol_case_does_not_split_a_finding_into_gone_plus_new():
    after = dataclasses.replace(now("f1"), protocol="tcp")
    before = dataclasses.replace(rec("f1"), protocol="TCP")
    result = diff([before], [after])
    assert result.id_reuse == 0 and [c.category for c in result.changes] == ["still_active"]


def test_fixed_findings_do_not_count_as_possible_rekeys():
    before = [rec("old", state="FIXED"), rec("k", plugin=2)]
    after = [now("new", state="FIXED"), now("k", plugin=2)]
    assert diff(before, after).possible_rekeys == 0
