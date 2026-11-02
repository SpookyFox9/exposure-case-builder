"""Regressions from the review of the MCP server, service and disposition log (commit 34909ac)."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import exposure_case.disposition as dlog
from exposure_case import service
from exposure_case.service import ServiceError, Workspace

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample"
AS_OF = datetime(2026, 11, 2, tzinfo=timezone.utc)
T0 = datetime(2026, 11, 3, tzinfo=timezone.utc)
GOOD = {
    "item_id": "plugin:1",
    "kind": "case",
    "analyst": "a",
    "disposition": "assigned",
    "note": "n",
    "recorded_at": "2026-11-03T00:00:00+00:00",
    "data_as_of": "2026-11-02T00:00:00+00:00",
}


@pytest.fixture
def ws(tmp_path):
    return Workspace.load(SAMPLE, exports_dir=tmp_path / "exports", dispositions_path=tmp_path / "d.jsonl")


def write_log(path: Path, *lines: str) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def first_case(ws):
    return ws.case_queue(kind="threats", top_n=1)["items"][0]["case_id"]


# --- the log must not be a single point of failure ---


def test_lenient_read_skips_bad_lines_and_reports_them(tmp_path):
    path = tmp_path / "d.jsonl"
    write_log(
        path,
        json.dumps(GOOD),
        "not json",
        json.dumps({**GOOD, "item_id": ["x"]}),
        "[" * 100000,
        json.dumps({**GOOD, "note": 5}),
        json.dumps({**GOOD, "item_id": "plugin:2"}),
    )
    entries, bad = dlog.read_dispositions_lenient(path)
    assert [e.item_id for e in entries] == ["plugin:1", "plugin:2"] and bad == (2, 3, 4, 5)


def test_strict_read_still_refuses_corrupt_logs(tmp_path):
    path = tmp_path / "d.jsonl"
    write_log(path, json.dumps({**GOOD, "item_id": ["x"]}))
    with pytest.raises(dlog.DispositionError, match="line 1"):
        dlog.read_dispositions(path)


def test_a_corrupt_log_does_not_break_the_queues(ws, tmp_path):
    write_log(tmp_path / "d.jsonl", json.dumps(GOOD), "garbage", json.dumps({**GOOD, "item_id": {"a": 1}}))
    assert ws.case_queue(top_n=2)["threats"]
    assert ws.fix_queue(top_n=1)["items"]
    summary = ws.fleet_summary()
    assert summary["log_warnings"] == 2 and any("disposition log" in n for n in summary["notes"])


def test_log_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(dlog, "MAX_LOG_BYTES", 400)
    path = tmp_path / "d.jsonl"
    with pytest.raises(dlog.DispositionError, match="full"):
        for _ in range(50):
            dlog.record_disposition(
                path,
                item_id="plugin:1",
                kind="case",
                analyst="a",
                disposition="assigned",
                note="n" * 100,
                confirm=True,
                data_as_of=AS_OF,
                clock=lambda: T0,
            )
    assert path.stat().st_size < 1200


def test_log_reads_are_cached_until_the_file_changes(ws, tmp_path, monkeypatch):
    calls = {"n": 0}
    real = dlog.read_dispositions_lenient

    def counting(path):
        calls["n"] += 1
        return real(path)

    monkeypatch.setattr(service.dlog, "read_dispositions_lenient", counting)
    ws.case_queue(top_n=1)
    ws.fix_queue(top_n=1)
    ws.fleet_summary()
    assert calls["n"] == 1
    ws.record_disposition(first_case(ws), "a", "assigned", "n", confirm=True)
    ws.case_queue(top_n=1)
    assert calls["n"] == 2


# --- cost and size ---


def test_case_files_and_packages_are_built_once(ws, monkeypatch):
    built = {"case": 0, "package": 0}
    real_case, real_pkg = service.build_case_file, service.build_package_view

    def count_case(*a, **k):
        built["case"] += 1
        return real_case(*a, **k)

    def count_pkg(*a, **k):
        built["package"] += 1
        return real_pkg(*a, **k)

    monkeypatch.setattr(service, "build_case_file", count_case)
    monkeypatch.setattr(service, "build_package_view", count_pkg)
    cid = first_case(ws)
    pid = ws.fix_queue(top_n=1)["items"][0]["package_id"]
    for _ in range(3):
        ws.case_file(cid)
        ws.export(cid, "markdown")
        ws.fix_package(pid)
        ws.export(pid, "markdown")
    assert built == {"case": 1, "package": 1}


def test_inline_exports_are_capped_with_a_pointer_to_write(ws, monkeypatch):
    monkeypatch.setattr(service, "MAX_INLINE_CHARS", 500)
    out = ws.export(first_case(ws), "markdown")
    assert out["truncated"] is True and len(out["content"]) <= 500 + 200 and "write=true" in out["note"]
    assert out["total_chars"] > 500


def test_small_inline_exports_are_not_marked_truncated(ws):
    assert ws.export(first_case(ws), "markdown").get("truncated") is False


def test_vulnerability_solution_text_is_shortened_in_tool_output(ws):
    cid = ws.case_queue(kind="backlogs", top_n=1)["items"][0]["case_id"]
    for v in ws.case_file(cid, max_vulns=100)["vulnerabilities"]:
        assert len(v["solution"]) <= service.MAX_SOLUTION_CHARS + 1


def test_vulnerability_limit_is_lower_than_other_lists(ws):
    with pytest.raises(ServiceError, match="max_vulns"):
        ws.case_file(first_case(ws), max_vulns=101)
    assert ws.case_file(first_case(ws), max_hosts=500)["hosts_total"] >= 1


# --- no absolute paths reach the model ---


def test_written_exports_are_reported_by_name_only(ws, tmp_path):
    out = ws.export(first_case(ws), "markdown", write=True, confirm=True)
    assert out["written"] and all("/" not in n and "\\" not in n for n in out["written"])
    assert all((tmp_path / "exports" / n).exists() for n in out["written"])
    assert "directory" in out and str(tmp_path) not in json.dumps(out)


# --- honest wording ---


def test_confirm_errors_do_not_claim_to_verify_a_human(ws):
    with pytest.raises(ServiceError) as exc:
        ws.export(first_case(ws), "markdown", write=True)
    assert "cannot verify" in str(exc.value)
    with pytest.raises(ServiceError) as exc2:
        ws.record_disposition(first_case(ws), "a", "assigned", "n", confirm=False)
    assert "cannot verify" in str(exc2.value)
