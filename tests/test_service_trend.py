import pytest
from test_baseline import write_pull
from test_ingest import raw_record

from exposure_case.service import ServiceError, Workspace
from exposure_case.trend import CATEGORIES
from exposure_case.trend_view import TREND_NOTE

ROW_KEYS = {
    "finding_id",
    "category",
    "asset_uuid",
    "plugin_id",
    "severity_before",
    "severity_after",
    "state_before",
    "state_after",
    "scan_uuid_before",
    "scan_uuid_after",
}


def r(fid, asset, plugin, last, state="OPEN", first="2026-05-01"):
    rec = raw_record(finding_id=fid, state=state, first_found=f"{first}T00:00:00Z", last_found=f"{last}T00:00:00Z")
    rec["asset"]["uuid"] = asset
    rec["plugin"]["id"] = plugin
    return rec


@pytest.fixture
def pulls(tmp_path):
    old = [r("f1", "a1", 1, "2026-10-01"), r("f2", "a2", 2, "2026-10-01"), r("f3", "a1", 3, "2026-10-01")]
    new = [
        r("f1", "a1", 1, "2026-11-01", state="FIXED"),  # fixed_recorded
        r("f2", "a2", 2, "2026-11-01"),  # still_active
        r("f9", "a1", 9, "2026-11-01", first="2026-10-25"),  # new_since_baseline
        # f3 is gone on a host that was scanned again: not_seen_rescanned
    ]
    return write_pull(tmp_path / "current", new), write_pull(tmp_path / "old", old)


def workspace(tmp_path, data, baseline=None):
    return Workspace.load(
        data, exports_dir=tmp_path / "e", dispositions_path=tmp_path / "d.jsonl", baseline_dir=baseline
    )


def test_without_a_baseline_the_tool_says_so(tmp_path, pulls):
    data, _ = pulls
    answer = workspace(tmp_path, data).trend_diff()
    assert answer["configured"] is False and "EXPOSURE_CASE_BASELINE" in answer["note"]
    assert workspace(tmp_path, data).trend_diff(category="reopened")["configured"] is False


def test_the_summary_counts_every_category_and_shows_host_overlap(tmp_path, pulls):
    data, old = pulls
    s = workspace(tmp_path, data, old).trend_diff()
    assert s["configured"] is True and s["synthetic"] is False
    assert tuple(s["findings"]) == CATEGORIES
    assert s["findings"]["fixed_recorded"] == 1 and s["findings"]["still_active"] == 1
    assert s["findings"]["new_since_baseline"] == 1 and s["findings"]["not_seen_rescanned"] == 1
    assert s["hosts"] == {"baseline": 2, "current": 2, "in_both": 2, "only_baseline": 0, "only_current": 0}
    assert s["data_quality"] == {"id_reuse": 0, "possible_rekeys": 0}
    assert s["baseline_as_of"].startswith("2026-10-01") and s["current_as_of"].startswith("2026-11-01")
    assert s["note"] == TREND_NOTE


def test_the_note_never_calls_absence_a_fix(tmp_path, pulls):
    note = TREND_NOTE.lower()
    for phrase in ("not present", "recorded no fix", "may not have been scanned", "newly_visible", "not new risk"):
        assert phrase in note, phrase


def test_a_category_page_lists_ids_and_facts_only(tmp_path, pulls):
    data, old = pulls
    page = workspace(tmp_path, data, old).trend_diff(category="fixed_recorded")
    assert page["total"] == 1 and page["category"] == "fixed_recorded" and page["offset"] == 0
    row = page["rows"][0]
    assert set(row) == ROW_KEYS and row["finding_id"] == "f1"
    assert row["state_before"] == "OPEN" and row["state_after"] == "FIXED"


def test_paging_walks_without_overlap(tmp_path):
    old = write_pull(tmp_path / "old", [r(f"f{i}", "a1", i, "2026-10-01") for i in range(1, 6)])
    new = write_pull(tmp_path / "new", [r(f"f{i}", "a1", i, "2026-11-01") for i in range(1, 6)])
    ws = workspace(tmp_path, new, old)
    first = ws.trend_diff(category="still_active", limit=2, offset=0)["rows"]
    second = ws.trend_diff(category="still_active", limit=2, offset=2)["rows"]
    third = ws.trend_diff(category="still_active", limit=2, offset=4)["rows"]
    ids = [row["finding_id"] for row in first + second + third]
    assert ids == sorted(set(ids)) and len(ids) == 5


@pytest.mark.parametrize(
    "kwargs",
    [
        {"category": "fixed"},
        {"category": 3},
        {"limit": 0},
        {"limit": 101},
        {"limit": "5"},
        {"offset": -1},
        {"offset": True},
    ],
)
def test_bad_arguments_are_service_errors(tmp_path, pulls, kwargs):
    data, old = pulls
    ws = workspace(tmp_path, data, old)
    with pytest.raises(ServiceError):
        ws.trend_diff(**{"category": "still_active", **kwargs})


def test_a_synthetic_baseline_is_labelled_in_the_answer(tmp_path, pulls):
    data, _ = pulls
    fake = write_pull(
        tmp_path / "fake", [r("f1", "a1", 1, "2026-10-01"), r("f2", "a2", 2, "2026-10-01")], synthetic=True
    )
    s = workspace(tmp_path, data, fake).trend_diff()
    assert s["synthetic"] is True and any("synthetic" in n.lower() for n in s["notes"])


def test_an_unusable_baseline_stops_the_load_with_a_service_error(tmp_path, pulls):
    data, _ = pulls
    newer = write_pull(tmp_path / "newer", [r("f1", "a1", 1, "2026-12-01")])
    with pytest.raises(ServiceError, match="newer"):
        workspace(tmp_path, data, newer)


def test_the_other_tools_are_unchanged_by_a_baseline(tmp_path, pulls):
    data, old = pulls
    plain, with_baseline = workspace(tmp_path, data), workspace(tmp_path, data, old)
    assert plain.fleet_summary() == with_baseline.fleet_summary()
    assert plain.fix_queue() == with_baseline.fix_queue()
