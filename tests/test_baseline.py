import json
from pathlib import Path

import pytest
from test_ingest import raw_record

from exposure_case.baseline import SYNTHETIC_MARKER, Baseline, BaselineError, load_baseline
from exposure_case.ingest import load_findings


def raw(fid, asset="a1", plugin=1, last="2026-10-01"):
    r = raw_record(finding_id=fid, last_found=f"{last}T00:00:00Z")
    r["asset"]["uuid"] = asset
    r["plugin"]["id"] = plugin
    return r


def write_pull(directory: Path, raws, synthetic=False) -> Path:
    (directory / "chunks").mkdir(parents=True)
    (directory / "chunks" / "chunk_1.json").write_text(json.dumps(list(raws)), encoding="utf-8")
    if synthetic:
        (directory / SYNTHETIC_MARKER).write_text("generated for a demo", encoding="utf-8")
    return directory


@pytest.fixture
def current(tmp_path):
    data = write_pull(tmp_path / "current", [raw("f1", "a1", 1, "2026-11-01"), raw("f2", "a2", 2, "2026-11-01")])
    return data, load_findings(data)


def test_a_valid_older_baseline_loads(tmp_path, current):
    data, records = current
    path = write_pull(tmp_path / "old", [raw("f1", "a1", 1), raw("f2", "a2", 2)])
    result = load_baseline(path, data, records)
    assert isinstance(result, Baseline) and len(result.records) == 2
    assert result.synthetic is False and result.notes == ()


def test_a_missing_directory_is_refused(tmp_path, current):
    data, records = current
    with pytest.raises(BaselineError, match="not found"):
        load_baseline(tmp_path / "nope", data, records)


def test_the_baseline_cannot_be_the_data_directory(current):
    data, records = current
    with pytest.raises(BaselineError, match="same"):
        load_baseline(data, data, records)


def test_the_baseline_cannot_reach_the_data_directory_through_a_relative_path(tmp_path, current):
    data, records = current
    sneaky = tmp_path / "x" / ".." / "current"
    (tmp_path / "x").mkdir()
    with pytest.raises(BaselineError, match="same"):
        load_baseline(sneaky, data, records)


def test_a_baseline_newer_than_the_current_pull_is_refused(tmp_path, current):
    data, records = current
    path = write_pull(tmp_path / "newer", [raw("f1", "a1", 1, "2026-12-01")])
    with pytest.raises(BaselineError, match="newer"):
        load_baseline(path, data, records)


def test_a_baseline_from_the_same_moment_is_allowed_with_a_note(tmp_path, current):
    data, records = current
    path = write_pull(tmp_path / "same", [raw("f1", "a1", 1, "2026-11-01"), raw("f2", "a2", 2, "2026-11-01")])
    assert any("same pull" in n for n in load_baseline(path, data, records).notes)


def test_no_shared_hosts_is_refused(tmp_path, current):
    data, records = current
    path = write_pull(tmp_path / "other", [raw("g1", "z1", 5)])
    with pytest.raises(BaselineError, match="no host"):
        load_baseline(path, data, records)


def test_low_host_overlap_is_a_warning_not_a_refusal(tmp_path, current):
    data, records = current
    others = [raw(f"g{i}", f"z{i}", 10 + i) for i in range(5)]
    path = write_pull(tmp_path / "mostly-other", [raw("f1", "a1", 1), *others])
    notes = load_baseline(path, data, records).notes
    assert any("overlap" in n for n in notes)


def test_an_empty_export_is_refused(tmp_path, current):
    data, records = current
    path = write_pull(tmp_path / "empty", [])
    with pytest.raises(BaselineError, match="empty"):
        load_baseline(path, data, records)


def test_a_malformed_baseline_becomes_a_baseline_error_naming_the_baseline(tmp_path, current):
    data, records = current
    (tmp_path / "bad" / "chunks").mkdir(parents=True)
    (tmp_path / "bad" / "chunks" / "chunk_1.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(BaselineError, match="baseline"):
        load_baseline(tmp_path / "bad", data, records)


def test_a_synthetic_marker_is_reported(tmp_path, current):
    data, records = current
    path = write_pull(tmp_path / "demo", [raw("f1", "a1", 1), raw("f2", "a2", 2)], synthetic=True)
    result = load_baseline(path, data, records)
    assert result.synthetic is True and any("synthetic" in n.lower() for n in result.notes)


def test_a_file_instead_of_a_directory_is_refused(tmp_path, current):
    data, records = current
    f = tmp_path / "file.json"
    f.write_text("[]", encoding="utf-8")
    with pytest.raises(BaselineError, match="not found"):
        load_baseline(f, data, records)


def test_synthetic_scan_ids_mark_a_baseline_even_if_the_marker_file_is_deleted(tmp_path, current):
    data, records = current
    marked = raw("f1", "a1", 1)
    marked["scan"]["uuid"] = "synthetic-1234"
    path = write_pull(tmp_path / "renamed", [marked, raw("f2", "a2", 2)])
    result = load_baseline(path, data, records)
    assert result.synthetic is True and any("synthetic" in n.lower() for n in result.notes)


def test_a_chunks_link_into_the_data_directory_is_refused(tmp_path, current):
    data, records = current
    fake = tmp_path / "linked"
    fake.mkdir()
    try:
        (fake / "chunks").symlink_to(data / "chunks", target_is_directory=True)
    except OSError:
        pytest.skip("cannot create symlinks here")
    with pytest.raises(BaselineError, match="same"):
        load_baseline(fake, data, records)


def test_a_baseline_with_only_informational_findings_is_refused(tmp_path, current):
    data, records = current
    info = raw("i1", "a1", 1)
    info["severity"] = "info"
    path = write_pull(tmp_path / "info-only", [info, {**raw("i2", "a2", 2), "severity": "info"}])
    with pytest.raises(BaselineError, match="no non-informational"):
        load_baseline(path, data, records)


def test_an_empty_current_export_is_a_baseline_error_not_a_bare_value_error(tmp_path):
    path = write_pull(tmp_path / "old", [raw("f1", "a1", 1)])
    with pytest.raises(BaselineError, match="current"):
        load_baseline(path, tmp_path / "somewhere", [])
