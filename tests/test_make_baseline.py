import importlib.util
import json
import sys
from pathlib import Path

import pytest

from exposure_case.baseline import SYNTHETIC_MARKER, load_baseline
from exposure_case.ingest import load_findings
from exposure_case.trend import diff

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "sample"


def _load_script():
    spec = importlib.util.spec_from_file_location("make_baseline", ROOT / "scripts" / "make_baseline.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["make_baseline"] = module
    spec.loader.exec_module(module)
    return module


script = _load_script()


@pytest.fixture(scope="module")
def baseline_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("baseline") / "demo"
    assert script.main([str(SAMPLE), str(out)]) == 0
    return out


def test_the_baseline_is_marked_synthetic_and_loads(baseline_dir):
    assert (baseline_dir / SYNTHETIC_MARKER).is_file()
    assert load_findings(baseline_dir)


def test_it_is_a_valid_older_baseline_for_the_sample(baseline_dir):
    current = load_findings(SAMPLE)
    result = load_baseline(baseline_dir, SAMPLE, current)
    assert result.synthetic is True and result.records


def test_it_exercises_the_trend_categories(baseline_dir):
    current = load_findings(SAMPLE)
    counts = diff(load_findings(baseline_dir), current).counts
    nonzero = {k for k, n in counts.items() if n}
    assert {
        "new_since_baseline",
        "newly_visible",
        "fixed_recorded",
        "reopened",
        "not_seen_rescanned",
        "severity_raised",
        "severity_lowered",
        "still_active",
    } <= nonzero


def test_generation_is_deterministic(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    assert script.main([str(SAMPLE), str(a)]) == 0 and script.main([str(SAMPLE), str(b)]) == 0
    assert (a / "chunks" / "chunk_1.json").read_bytes() == (b / "chunks" / "chunk_1.json").read_bytes()


def test_finding_ids_that_existed_before_keep_their_ids(baseline_dir):
    before = {r.finding_id for r in load_findings(baseline_dir)}
    current = {r.finding_id for r in load_findings(SAMPLE)}
    assert len(before & current) > len(before) // 2


def test_the_source_is_never_modified(tmp_path):
    snapshot = (SAMPLE / "chunks" / "chunk_1.json").read_bytes()
    script.main([str(SAMPLE), str(tmp_path / "out")])
    assert (SAMPLE / "chunks" / "chunk_1.json").read_bytes() == snapshot


def test_it_refuses_to_write_into_the_source_or_a_non_empty_directory(tmp_path):
    assert script.main([str(SAMPLE), str(SAMPLE)]) == 1
    busy = tmp_path / "busy"
    busy.mkdir()
    (busy / "keep.txt").write_text("x", encoding="utf-8")
    assert script.main([str(SAMPLE), str(busy)]) == 1
    assert (busy / "keep.txt").read_text(encoding="utf-8") == "x"


def test_a_missing_source_is_an_error_not_a_traceback(tmp_path):
    assert script.main([str(tmp_path / "nope"), str(tmp_path / "out")]) == 1
    assert not (tmp_path / "out").exists()


def test_output_is_plain_json_with_no_plugin_output_added(baseline_dir):
    data = json.loads((baseline_dir / "chunks" / "chunk_1.json").read_text(encoding="utf-8"))
    assert isinstance(data, list) and data
    sample = json.loads((SAMPLE / "chunks" / "chunk_1.json").read_text(encoding="utf-8"))
    longest_sample = max(len(r.get("output", "")) for r in sample)
    assert max(len(r.get("output", "")) for r in data) <= longest_sample


def test_scan_ids_are_visibly_synthetic_so_the_marker_file_is_not_the_only_label(baseline_dir):
    scans = {r.scan_uuid for r in load_findings(baseline_dir)}
    assert scans and all(s.startswith("synthetic-") for s in scans)


def test_plugin_output_is_not_copied_into_the_synthetic_baseline(baseline_dir):
    data = json.loads((baseline_dir / "chunks" / "chunk_1.json").read_text(encoding="utf-8"))
    assert all(not r.get("output") for r in data)


def test_a_malformed_source_record_fails_cleanly_and_leaves_no_output(tmp_path):
    src = tmp_path / "src"
    (src / "chunks").mkdir(parents=True)
    (src / "chunks" / "chunk_1.json").write_text(json.dumps([{"finding_id": "x"}]), encoding="utf-8")
    assert script.main([str(src), str(tmp_path / "out")]) == 1
    assert not (tmp_path / "out").exists()
