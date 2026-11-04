import importlib.util
import json
from pathlib import Path

import pytest

from exposure_case.ingest import load_findings, load_plugin_info

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "make_sample.py"
spec = importlib.util.spec_from_file_location("make_sample", SCRIPT)
ms = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ms)


def rec(fid, asset, plugin, severity="high", state="OPEN", output="x" * 500, **plugin_extra):
    return {
        "finding_id": fid,
        "state": state,
        "severity": severity,
        "first_found": "2026-06-01T00:00:00.000Z",
        "last_found": "2026-11-01T00:00:00.000Z",
        "output": output,
        "indexed": "drop-me",
        "asset": {
            "uuid": asset,
            "hostname": f"H-{asset}",
            "ipv4": "10.0.0.1",
            "device_type": "general-purpose",
            "operating_system": ["Linux"],
            "network_id": "drop-me",
        },
        "plugin": {
            "id": plugin,
            "name": f"P{plugin}",
            "family": "F",
            "synopsis": "s",
            "description": "drop " * 200,
            "exploit_available": True,
            "has_patch": True,
            "xrefs": [1, 2, 3],
            **plugin_extra,
        },
        "port": {"port": 22, "protocol": "TCP", "service": "ssh"},
        "scan": {"uuid": "s1", "started_at": "2026-11-01T00:00:00.000Z"},
    }


@pytest.fixture
def source(tmp_path):
    """6 assets x plugins 100,101,102 (common), plus info plugin 999, a malware plugin 200 on one
    asset, a reopened plugin 201 on one asset, and a plain rare plugin 300 on one asset."""
    src = tmp_path / "src"
    (src / "chunks").mkdir(parents=True)
    records = []
    for a in range(6):
        for p in range(3):
            records.append(rec(f"f-{a}-{p}", f"asset-{a}", 100 + p))
        records.append(rec(f"info-{a}", f"asset-{a}", 999, severity="info"))
    records.append(rec("m-1", "asset-0", 200, exploited_by_malware=True))
    records.append(rec("r-1", "asset-1", 201, state="REOPENED"))
    records.append(rec("x-1", "asset-2", 300))
    (src / "chunks" / "chunk_1.json").write_text(json.dumps(records), encoding="utf-8")
    (src / "plugins.json").write_text(
        json.dumps(
            {"vulnerabilities": [{"plugin_id": 100, "count": 6, "vpr_score": 5.0}, {"plugin_id": 555, "count": 1}]}
        ),
        encoding="utf-8",
    )
    return src


def plugin_ids(out):
    return {r.plugin_id for r in load_findings(out)}


def test_top_plugins_by_asset_count_tie_broken_by_id(source, tmp_path):
    out = tmp_path / "out"
    ms.build_sample(source, out, n_plugins=2, n_notable=0)
    assert plugin_ids(out) == {100, 101}
    assert len(load_findings(out)) == 12  # all 6 assets kept for each chosen plugin


def test_notable_plugins_added_malware_and_reopened(source, tmp_path):
    out = tmp_path / "out"
    ms.build_sample(source, out, n_plugins=1, n_notable=2)
    assert plugin_ids(out) == {100, 200, 201}


def test_info_findings_never_kept(source, tmp_path):
    out = tmp_path / "out"
    ms.build_sample(source, out, n_plugins=10, n_notable=10)
    assert all(r.severity != "info" for r in load_findings(out))
    assert 999 not in plugin_ids(out)


def test_sample_is_deterministic(source, tmp_path):
    ms.build_sample(source, tmp_path / "a", n_plugins=2, n_notable=1)
    ms.build_sample(source, tmp_path / "b", n_plugins=2, n_notable=1)
    assert (tmp_path / "a" / "chunks" / "chunk_1.json").read_bytes() == (
        tmp_path / "b" / "chunks" / "chunk_1.json"
    ).read_bytes()


def test_sample_strips_unused_fields_and_truncates_output(source, tmp_path):
    out = tmp_path / "out"
    ms.build_sample(source, out, n_plugins=2, n_notable=0)
    r = json.loads((out / "chunks" / "chunk_1.json").read_text(encoding="utf-8"))[0]
    assert "indexed" not in r and "network_id" not in r["asset"]
    assert "description" not in r["plugin"] and "xrefs" not in r["plugin"]
    assert "output" not in r  # plugin output can hold personal data and is never exposed by a tool


def test_sample_plugin_rows_limited_to_kept_plugins(source, tmp_path):
    out = tmp_path / "out"
    ms.build_sample(source, out, n_plugins=2, n_notable=0)
    assert set(load_plugin_info(out)) == {100}


def test_sample_rejects_non_empty_output(source, tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "keep").write_text("x")
    with pytest.raises(ValueError, match="not empty"):
        ms.build_sample(source, out)


def test_sample_rejects_bad_counts(source, tmp_path):
    with pytest.raises(ValueError, match="n_plugins"):
        ms.build_sample(source, tmp_path / "out", n_plugins=0)


def test_sample_chunks_stay_under_the_size_limit(source, tmp_path, monkeypatch):
    # The Exchange's reviewers flag committed files over 1 MB (PR #216, item 25); the sample was 1.56 MB in one file.
    monkeypatch.setattr(ms, "MAX_CHUNK_BYTES", 3000)
    out = tmp_path / "out"
    ms.build_sample(source, out, n_plugins=10, n_notable=10)
    chunks = sorted((out / "chunks").glob("chunk_*.json"))
    assert len(chunks) > 1 and all(c.stat().st_size <= 3000 for c in chunks)
    whole = tmp_path / "whole"
    monkeypatch.setattr(ms, "MAX_CHUNK_BYTES", 10**9)
    ms.build_sample(source, whole, n_plugins=10, n_notable=10)
    assert load_findings(out) == load_findings(whole)


def test_committed_sample_files_are_each_under_one_megabyte():
    sample = Path(__file__).resolve().parent.parent / "data" / "sample"
    sizes = {p.name: p.stat().st_size for p in sample.rglob("*.json")}
    assert sizes and all(size < 1_000_000 for size in sizes.values()), sizes
