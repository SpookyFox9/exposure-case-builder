import dataclasses
import json
from datetime import timezone

import pytest

from exposure_case.ingest import (
    FindingRecord,
    IngestError,
    load_findings,
    load_plugin_info,
    parse_record,
)


def raw_record(**overrides):
    rec = {
        "finding_id": "f-1",
        "state": "OPEN",
        "severity": "high",
        "first_found": "2026-05-24T09:01:36.766Z",
        "last_found": "2026-11-01T09:53:31.466Z",
        "output": "\nA CIFS server is running on this port.\n",
        "asset": {
            "uuid": "a-1",
            "hostname": "HOST1",
            "ipv4": "172.26.0.62",
            "device_type": "general-purpose",
            "operating_system": ["Ubuntu Linux 14.04"],
        },
        "plugin": {
            "id": 11011,
            "name": "SMB Service Detection",
            "family": "Windows",
            "synopsis": "A file sharing service is listening.",
            "exploit_available": True,
            "exploited_by_malware": False,
            "in_the_news": False,
            "has_patch": True,
            "unsupported_by_vendor": False,
            "checks_for_default_account": False,
        },
        "port": {"port": 445, "protocol": "TCP", "service": "cifs"},
        "scan": {"uuid": "s-1", "started_at": "2026-11-01T09:02:13.812Z"},
    }
    rec.update(overrides)
    return rec


def test_parse_record_maps_fields():
    r = parse_record(raw_record())
    assert isinstance(r, FindingRecord)
    assert (r.finding_id, r.plugin_id, r.state, r.severity) == ("f-1", 11011, "OPEN", "high")
    assert r.asset_uuid == "a-1" and r.hostname == "HOST1"
    assert r.operating_system == ("Ubuntu Linux 14.04",)
    assert r.port == 445 and r.protocol == "TCP"
    assert r.exploit_available is True and r.has_patch is True
    assert r.scan_uuid == "s-1"


def test_parse_record_timestamps_are_aware_utc():
    r = parse_record(raw_record())
    assert r.first_found.tzinfo == timezone.utc
    assert r.first_found < r.last_found


def test_parse_record_is_frozen():
    r = parse_record(raw_record())
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.state = "FIXED"  # type: ignore[misc]


def test_evidence_points_at_finding_id():
    ev = parse_record(raw_record()).evidence()
    assert ev.to_dict() == {"source": "finding", "record_id": "f-1"}


def test_parse_record_tolerates_missing_optional_fields():
    raw = raw_record()
    del raw["asset"]["hostname"], raw["asset"]["ipv4"], raw["output"], raw["scan"]["started_at"]
    del raw["plugin"]["synopsis"], raw["asset"]["operating_system"], raw["port"]["service"]
    r = parse_record(raw)
    assert r.hostname == "" and r.ipv4 == "" and r.output == "" and r.scan_started is None
    assert r.operating_system == () and r.service == ""


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.pop("finding_id"),
        lambda r: r.pop("state"),
        lambda r: r["plugin"].pop("id"),
        lambda r: r["asset"].pop("uuid"),
        lambda r: r.update(first_found="not-a-date"),
        lambda r: r.update(finding_id="  "),
    ],
)
def test_parse_record_rejects_missing_or_bad_required_fields(mutate):
    raw = raw_record()
    mutate(raw)
    with pytest.raises(IngestError):
        parse_record(raw)


def test_unknown_state_is_rejected():
    with pytest.raises(IngestError, match="state"):
        parse_record(raw_record(state="WEIRD"))


def _write_chunks(tmp_path, *chunks):
    d = tmp_path / "chunks"
    d.mkdir()
    for i, chunk in enumerate(chunks, start=1):
        (d / f"chunk_{i}.json").write_text(json.dumps(chunk), encoding="utf-8")
    return tmp_path


def test_load_findings_reads_all_chunks_in_order(tmp_path):
    root = _write_chunks(
        tmp_path,
        [raw_record(finding_id="a")],
        [raw_record(finding_id="b"), raw_record(finding_id="c")],
    )
    assert [r.finding_id for r in load_findings(root)] == ["a", "b", "c"]


def test_load_findings_sorts_numerically_not_lexically(tmp_path):
    d = tmp_path / "chunks"
    d.mkdir()
    for n in (2, 10):
        (d / f"chunk_{n}.json").write_text(json.dumps([raw_record(finding_id=f"c{n}")]), encoding="utf-8")
    assert [r.finding_id for r in load_findings(tmp_path)] == ["c2", "c10"]


def test_load_findings_rejects_duplicate_ids(tmp_path):
    root = _write_chunks(tmp_path, [raw_record(finding_id="a")], [raw_record(finding_id="a")])
    with pytest.raises(IngestError, match="duplicate"):
        load_findings(root)


def test_load_findings_error_names_the_bad_file_and_index(tmp_path):
    bad = raw_record()
    del bad["state"]
    root = _write_chunks(tmp_path, [raw_record(finding_id="ok"), bad])
    with pytest.raises(IngestError, match=r"chunk_1\.json.*\[1\]"):
        load_findings(root)


def test_load_findings_missing_directory(tmp_path):
    with pytest.raises(IngestError, match="chunks"):
        load_findings(tmp_path)


def test_load_findings_rejects_non_list_chunk(tmp_path):
    root = _write_chunks(tmp_path, {"not": "a list"})
    with pytest.raises(IngestError, match="list"):
        load_findings(root)


def test_load_plugin_info_joins_by_plugin_id(tmp_path):
    (tmp_path / "plugins.json").write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {"plugin_id": 11011, "count": 7, "vpr_score": 6.1, "cvss_base_score": 5.0, "cvss3_base_score": 7.5},
                    {"plugin_id": 10114, "count": 3},
                ]
            }
        ),
        encoding="utf-8",
    )
    info = load_plugin_info(tmp_path)
    assert info[11011].vpr_score == 6.1 and info[11011].count == 7
    assert info[10114].vpr_score is None and info[10114].cvss3_base_score is None


def test_load_plugin_info_absent_file_returns_empty(tmp_path):
    assert load_plugin_info(tmp_path) == {}
