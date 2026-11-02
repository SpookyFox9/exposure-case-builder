"""Hardening tests for the sample builder (from code review)."""

import json

import pytest
from test_make_sample import ms, rec, source  # noqa: F401  (source is a fixture)


def test_malformed_record_is_a_clear_error(source, tmp_path):  # noqa: F811
    (source / "chunks" / "chunk_2.json").write_text(json.dumps([{"finding_id": "x"}]), encoding="utf-8")
    with pytest.raises(ms.IngestError):
        ms.build_sample(source, tmp_path / "out")


def test_missing_chunks_directory(tmp_path):
    with pytest.raises(ms.IngestError, match="chunks"):
        ms.build_sample(tmp_path, tmp_path / "out")


def test_chunks_read_in_numeric_order(tmp_path):
    src = tmp_path / "src"
    (src / "chunks").mkdir(parents=True)
    for n in (10, 2):
        body = json.dumps([rec(f"f{n}", f"a{n}", 100)])
        (src / "chunks" / f"chunk_{n}.json").write_text(body, encoding="utf-8")
    ms.build_sample(src, tmp_path / "out", n_plugins=1, n_notable=0)
    out = json.loads((tmp_path / "out" / "chunks" / "chunk_1.json").read_text(encoding="utf-8"))
    assert [r["finding_id"] for r in out] == ["f2", "f10"]


def test_plugins_json_that_is_a_list_is_an_error(source, tmp_path):  # noqa: F811
    (source / "plugins.json").write_text("[]", encoding="utf-8")
    with pytest.raises(ms.IngestError):
        ms.build_sample(source, tmp_path / "out")


def test_main_exit_codes(source, tmp_path, capsys):  # noqa: F811
    assert ms.main([str(source), str(tmp_path / "ok"), "--plugins", "2", "--notable", "0"]) == 0
    assert ms.main([str(tmp_path / "missing"), str(tmp_path / "bad")]) == 1
    assert "error" in capsys.readouterr().err
