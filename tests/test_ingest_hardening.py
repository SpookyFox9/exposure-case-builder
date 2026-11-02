"""Hardening tests for untrusted export data (from code review)."""

import json
from datetime import timezone

import pytest
from test_ingest import _write_chunks, raw_record

import exposure_case.ingest as ing
from exposure_case.ingest import IngestError, load_findings, load_plugin_info, parse_record


@pytest.mark.parametrize(
    "ts",
    [
        "2026-05-24T09:01:36.7Z",
        "2026-05-24T09:01:36.76Z",
        "2026-05-24T09:01:36.7654Z",
        "2026-05-24T09:01:36.765432Z",
        "2026-05-24T09:01:36Z",
        "2026-05-24T09:01:36+0000",
    ],
)
def test_timestamps_with_any_fraction_length_parse(ts):
    r = parse_record(raw_record(first_found=ts))
    assert r.first_found.tzinfo == timezone.utc and r.first_found.year == 2026


def test_timestamp_with_embedded_z_is_rejected():
    with pytest.raises(IngestError, match="timestamp"):
        parse_record(raw_record(first_found="2026-05-24TZ09:01:36Z"))


def test_non_string_scalar_fields_do_not_become_reprs():
    raw = raw_record()
    raw["asset"]["hostname"] = {"a": 1}
    raw["asset"]["operating_system"] = ["Linux", {"x": 1}, 5]
    r = parse_record(raw)
    assert r.hostname == "" and r.operating_system == ("Linux",)


def test_invalid_utf8_chunk_is_ingest_error(tmp_path):
    d = tmp_path / "chunks"
    d.mkdir()
    (d / "chunk_1.json").write_bytes(b"\xff\xfe\x00bad")
    with pytest.raises(IngestError, match="chunk_1"):
        load_findings(tmp_path)


def test_deeply_nested_json_is_ingest_error(tmp_path):
    d = tmp_path / "chunks"
    d.mkdir()
    (d / "chunk_1.json").write_text("[" * 200000, encoding="utf-8")
    with pytest.raises(IngestError):
        load_findings(tmp_path)


def test_oversized_file_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(ing, "MAX_FILE_BYTES", 10)
    root = _write_chunks(tmp_path, [raw_record()])
    with pytest.raises(IngestError, match="too large"):
        load_findings(root)


def test_non_dict_element_names_file_and_index(tmp_path):
    root = _write_chunks(tmp_path, [raw_record(finding_id="ok"), "oops"])
    with pytest.raises(IngestError, match=r"chunk_1\.json\[1\]"):
        load_findings(root)


@pytest.mark.parametrize("body", ["[]", '{"vulnerabilities": "x"}', "not json"])
def test_malformed_plugins_json_is_ingest_error(tmp_path, body):
    (tmp_path / "plugins.json").write_text(body, encoding="utf-8")
    with pytest.raises(IngestError):
        load_plugin_info(tmp_path)


def test_plugins_json_skips_non_dict_rows(tmp_path):
    body = json.dumps({"vulnerabilities": ["x", {"plugin_id": 1, "count": 2}]})
    (tmp_path / "plugins.json").write_text(body, encoding="utf-8")
    assert set(load_plugin_info(tmp_path)) == {1}
