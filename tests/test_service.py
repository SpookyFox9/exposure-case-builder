import json
from pathlib import Path

import pytest

from exposure_case.ingest import load_findings
from exposure_case.service import ServiceError, Workspace

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample"


@pytest.fixture(scope="module")
def records():
    return load_findings(SAMPLE)


@pytest.fixture
def ws(tmp_path):
    return Workspace.load(SAMPLE, exports_dir=tmp_path / "exports", dispositions_path=tmp_path / "d.jsonl")


def first_case(ws, kind="threats"):
    return ws.case_queue(kind=kind, top_n=1)["items"][0]["case_id"] if kind != "both" else None


# --- loading ---

def test_missing_data_directory_is_a_clear_error(tmp_path):
    with pytest.raises(ServiceError, match="data"):
        Workspace.load(tmp_path / "nope", exports_dir=tmp_path / "e", dispositions_path=tmp_path / "d.jsonl")


# --- fleet summary ---

def test_fleet_summary_is_consistent(ws, records):
    s = ws.fleet_summary()
    active = [r for r in records if r.severity != "info" and r.state != "FIXED"]
    assert s["active_findings"] == len(active) and s["hosts"] == len({r.asset_uuid for r in records})
    assert s["cases"]["total"] == s["cases"]["threats"] + s["cases"]["backlogs"]
    assert sum(s["by_severity"].values()) == len(active)
    assert s["fix_packages"]["total"] >= 1 and s["as_of"].startswith("2026-")
    assert any("masked" in note for note in s["notes"])


# --- queues ---

def test_case_queue_returns_two_lists_by_default(ws):
    q = ws.case_queue(top_n=5)
    assert set(q) == {"threats", "backlogs", "as_of"}
    assert all(i["kind"] == "plugin" for i in q["threats"])
    assert all(i["kind"] == "patch_family" for i in q["backlogs"])
    assert len(q["threats"]) <= 5 and len(q["backlogs"]) <= 5


def test_each_list_is_sorted_by_score_with_positions(ws):
    for items in (ws.case_queue(top_n=20)["threats"], ws.case_queue(top_n=20)["backlogs"]):
        scores = [i["score"] for i in items]
        assert scores == sorted(scores, reverse=True)
        assert [i["position"] for i in items] == list(range(1, len(items) + 1))
        assert [i["rank"] for i in items] == sorted(i["rank"] for i in items)


def test_queue_rows_explain_themselves(ws):
    row = ws.case_queue(kind="threats", top_n=1)["items"][0]
    assert row["why"] and row["fix_packages"] and row["disposition"] is None
    assert {"case_id", "title", "score", "worst_severity", "hosts", "vulnerabilities", "findings"} <= set(row)


def test_single_kind_queue_shape(ws):
    q = ws.case_queue(kind="backlogs", top_n=3)
    assert set(q) == {"kind", "items", "as_of"} and q["kind"] == "backlogs"


@pytest.mark.parametrize("kwargs", [{"kind": "everything"}, {"top_n": 0}, {"top_n": 51}, {"top_n": "5"}])
def test_queue_arguments_are_validated(ws, kwargs):
    with pytest.raises(ServiceError):
        ws.case_queue(**kwargs)


def test_fix_queue(ws):
    q = ws.fix_queue(top_n=5)
    assert len(q["items"]) == 5
    row = q["items"][0]
    assert row["package_id"].startswith("fix:") and row["actions"] >= 1 and "contained_critical_share" in row
    scores = [i["score"] for i in q["items"]]
    assert scores == sorted(scores, reverse=True)


def test_hide_dispositioned_removes_decided_items(ws):
    cid = first_case(ws)
    before = ws.case_queue(kind="threats", top_n=50)["items"]
    ws.record_disposition(cid, "analyst-1", "assigned", "ticket opened", confirm=True)
    after = ws.case_queue(kind="threats", top_n=50, hide_dispositioned=True)["items"]
    assert cid in [i["case_id"] for i in before] and cid not in [i["case_id"] for i in after]
    shown = ws.case_queue(kind="threats", top_n=50)["items"]
    assert next(i for i in shown if i["case_id"] == cid)["disposition"]["disposition"] == "assigned"


# --- case file ---

def test_case_file_is_capped_with_totals(ws):
    cid = ws.case_queue(kind="backlogs", top_n=1)["items"][0]["case_id"]
    cf = ws.case_file(cid, max_hosts=3, max_vulns=4, max_events=5)
    assert len(cf["hosts"]) <= 3 and cf["hosts_total"] >= len(cf["hosts"])
    assert len(cf["vulnerabilities"]) <= 4 and cf["vulnerabilities_total"] >= len(cf["vulnerabilities"])
    assert len(cf["timeline"]) <= 5 and cf["timeline_total"] >= len(cf["timeline"])
    assert cf["evidence_ids_total"] >= len(cf["evidence_ids"]) and cf["disposition"] is None
    assert cf["limitations"] and cf["score"]["components"]


def test_case_file_is_json_serialisable_and_deterministic(ws, tmp_path):
    cid = first_case(ws)
    a = ws.case_file(cid)
    json.dumps(a)
    other = Workspace.load(SAMPLE, exports_dir=tmp_path / "e2", dispositions_path=tmp_path / "d2.jsonl")
    assert other.case_file(cid) == a


def test_unknown_ids_are_clear_errors(ws):
    for call in (ws.case_file, ws.fix_package):
        with pytest.raises(ServiceError, match="unknown"):
            call("nope")
    with pytest.raises(ServiceError, match="unknown"):
        ws.findings("nope")


def test_case_file_shows_a_recorded_disposition(ws):
    cid = first_case(ws)
    ws.record_disposition(cid, "analyst-1", "needs-info", "waiting for the owner", confirm=True)
    d = ws.case_file(cid)["disposition"]
    assert d["disposition"] == "needs-info" and d["analyst"] == "analyst-1"


@pytest.mark.parametrize("kwargs", [{"max_hosts": 0}, {"max_hosts": 501}, {"max_vulns": -1}, {"max_events": "x"}])
def test_case_file_limits_validated(ws, kwargs):
    with pytest.raises(ServiceError):
        ws.case_file(first_case(ws), **kwargs)


# --- fix package ---

def test_fix_package_is_capped_and_scoped(ws):
    pid = ws.fix_queue(top_n=1)["items"][0]["package_id"]
    p = ws.fix_package(pid, max_hosts=2, max_actions=3)
    assert len(p["package"]["hosts"]) <= 2 and p["package"]["hosts_total"] >= len(p["package"]["hosts"])
    assert len(p["package"]["actions"]) <= 3 and p["actions_total"] >= len(p["package"]["actions"])
    assert "does not state" in p["scope_note"] and p["cases"]
    assert p["package"]["impact"]["actions"] == p["actions_total"]


# --- findings (so narratives can cite real ids) ---

def test_findings_page_real_records(ws, records):
    cid = first_case(ws)
    page = ws.findings(cid, limit=5)
    known = {r.finding_id for r in records}
    assert page["total"] >= len(page["findings"]) and len(page["findings"]) <= 5
    assert all(f["finding_id"] in known for f in page["findings"])
    ids = [f["finding_id"] for f in page["findings"]]
    assert ids == sorted(ids)


def test_findings_paging_walks_without_overlap(ws):
    cid = first_case(ws)
    first = ws.findings(cid, limit=2, offset=0)["findings"]
    second = ws.findings(cid, limit=2, offset=2)["findings"]
    assert not {f["finding_id"] for f in first} & {f["finding_id"] for f in second}


def test_findings_accepts_package_ids(ws):
    pid = ws.fix_queue(top_n=1)["items"][0]["package_id"]
    assert ws.findings(pid, limit=3)["total"] >= 1


@pytest.mark.parametrize("kwargs", [{"limit": 0}, {"limit": 101}, {"offset": -1}])
def test_findings_limits_validated(ws, kwargs):
    with pytest.raises(ServiceError):
        ws.findings(first_case(ws), **kwargs)


# --- exports ---

def test_export_returns_markdown_without_writing(ws, tmp_path):
    out = ws.export(first_case(ws), "markdown")
    assert out["content"].startswith("# Case:") and not (tmp_path / "exports").exists()


def test_export_package_formats(ws):
    pid = ws.fix_queue(top_n=1)["items"][0]["package_id"]
    assert ws.export(pid, "markdown")["content"].startswith("# Fix:")
    assert ws.export(pid, "hosts_csv")["content"].startswith("asset_uuid,")
    assert ws.export(pid, "actions_csv")["content"].startswith("solution,")


def test_export_rejects_bad_requests(ws):
    cid = first_case(ws)
    with pytest.raises(ServiceError, match="format"):
        ws.export(cid, "pdf")
    with pytest.raises(ServiceError, match="for a case"):  # actions_csv exists only for fix packages
        ws.export(cid, "actions_csv")
    with pytest.raises(ServiceError, match="json"):
        ws.export(cid, "json")


def test_export_write_requires_confirm(ws, tmp_path):
    with pytest.raises(ServiceError, match="confirm"):
        ws.export(first_case(ws), "markdown", write=True)
    assert not (tmp_path / "exports").exists()


def test_export_write_creates_the_files(ws, tmp_path):
    out = ws.export(first_case(ws), "markdown", write=True, confirm=True)
    assert len(out["written"]) >= 3
    assert all(Path(p).parent == (tmp_path / "exports").resolve() and Path(p).exists() for p in out["written"])


# --- dispositions ---

def test_record_disposition_infers_kind_and_logs(ws, tmp_path):
    pid = ws.fix_queue(top_n=1)["items"][0]["package_id"]
    entry = ws.record_disposition(pid, "analyst-1", "assigned", "sent to platform", confirm=True)
    assert entry["kind"] == "fix_package" and entry["item_id"] == pid
    assert len((tmp_path / "d.jsonl").read_text(encoding="utf-8").splitlines()) == 1


def test_record_disposition_rejects_unknown_items_and_missing_confirm(ws, tmp_path):
    with pytest.raises(ServiceError, match="unknown"):
        ws.record_disposition("plugin:no-such", "a", "assigned", "n", confirm=True)
    with pytest.raises(ServiceError, match="confirm"):
        ws.record_disposition(first_case(ws), "a", "assigned", "n", confirm=False)
    assert not (tmp_path / "d.jsonl").exists()


def test_record_disposition_validation_errors_are_service_errors(ws):
    with pytest.raises(ServiceError, match="disposition"):
        ws.record_disposition(first_case(ws), "a", "fired", "n", confirm=True)
