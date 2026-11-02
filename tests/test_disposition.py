import json
from datetime import datetime, timezone

import pytest

from exposure_case.disposition import (
    DISPOSITIONS,
    Disposition,
    DispositionError,
    latest_by_item,
    read_dispositions,
    record_disposition,
)

AS_OF = datetime(2026, 11, 2, tzinfo=timezone.utc)
T0 = datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc)


def rec(path, **overrides):
    args = {"item_id": "plugin:1", "kind": "case", "analyst": "analyst-1", "disposition": "assigned",
                "note": "Sent to the platform team.", "confirm": True, "data_as_of": AS_OF, "clock": lambda: T0}
    return record_disposition(path, **{**args, **overrides})


def test_vocabulary_is_fixed():
    assert DISPOSITIONS == ("assigned", "risk-accepted", "false-positive", "needs-info")


def test_requires_confirm_and_writes_nothing_without_it(tmp_path):
    path = tmp_path / "d.jsonl"
    for bad in (False, None, "true", 1):
        with pytest.raises(DispositionError, match="confirm"):
            rec(path, confirm=bad)
    assert not path.exists()


def test_appends_one_json_line_with_all_fields(tmp_path):
    path = tmp_path / "d.jsonl"
    entry = rec(path)
    assert isinstance(entry, Disposition)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data == {"item_id": "plugin:1", "kind": "case", "analyst": "analyst-1", "disposition": "assigned",
                    "note": "Sent to the platform team.", "recorded_at": "2026-11-03T09:00:00+00:00",
                    "data_as_of": "2026-11-02T00:00:00+00:00"}


def test_log_is_append_only(tmp_path):
    path = tmp_path / "d.jsonl"
    rec(path, note="first")
    first_line = path.read_text(encoding="utf-8").splitlines()[0]
    rec(path, item_id="plugin:2", note="second")
    rec(path, note="third")
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3 and lines[0] == first_line


@pytest.mark.parametrize("bad", ["", "fired", "ASSIGNED", "terminate", None, 5])
def test_unknown_disposition_rejected(tmp_path, bad):
    with pytest.raises(DispositionError, match="disposition"):
        rec(tmp_path / "d.jsonl", disposition=bad)


@pytest.mark.parametrize("kind", ["person", "", "Case"])
def test_unknown_kind_rejected(tmp_path, kind):
    with pytest.raises(DispositionError, match="kind"):
        rec(tmp_path / "d.jsonl", kind=kind)


@pytest.mark.parametrize("analyst", ["", "   ", "x" * 81, "\x00\x1b"])
def test_analyst_must_be_present_and_bounded(tmp_path, analyst):
    with pytest.raises(DispositionError, match="analyst"):
        rec(tmp_path / "d.jsonl", analyst=analyst)


def test_note_is_bounded_and_cleaned(tmp_path):
    with pytest.raises(DispositionError, match="note"):
        rec(tmp_path / "d.jsonl", note="x" * 2001)
    entry = rec(tmp_path / "d.jsonl", note="line1\nline2\x00\u202egone")
    assert entry.note == "line1 line2gone"


@pytest.mark.parametrize("item", ["", "a\nb", "x" * 201, "\x00"])
def test_item_id_validated(tmp_path, item):
    with pytest.raises(DispositionError, match="item_id"):
        rec(tmp_path / "d.jsonl", item_id=item)


def test_naive_times_rejected(tmp_path):
    with pytest.raises(DispositionError, match="timezone"):
        rec(tmp_path / "d.jsonl", data_as_of=datetime(2026, 11, 2))
    with pytest.raises(DispositionError, match="timezone"):
        rec(tmp_path / "d.jsonl", clock=lambda: datetime(2026, 11, 3))


def test_creates_parent_directory(tmp_path):
    path = tmp_path / "nested" / "dir" / "d.jsonl"
    rec(path)
    assert path.exists()


def test_directory_path_is_an_error(tmp_path):
    with pytest.raises(DispositionError):
        rec(tmp_path)


def test_read_returns_entries_in_order(tmp_path):
    path = tmp_path / "d.jsonl"
    rec(path, note="a")
    rec(path, item_id="plugin:2", note="b")
    assert [(e.item_id, e.note) for e in read_dispositions(path)] == [("plugin:1", "a"), ("plugin:2", "b")]


def test_read_missing_file_is_empty(tmp_path):
    assert read_dispositions(tmp_path / "nope.jsonl") == ()


def test_read_names_the_corrupt_line(tmp_path):
    path = tmp_path / "d.jsonl"
    rec(path)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("not json\n")
    with pytest.raises(DispositionError, match="line 2"):
        read_dispositions(path)


def test_latest_wins_per_item(tmp_path):
    path = tmp_path / "d.jsonl"
    rec(path, disposition="needs-info", note="old")
    rec(path, disposition="assigned", note="new")
    rec(path, item_id="plugin:2", disposition="false-positive")
    latest = latest_by_item(read_dispositions(path))
    assert latest["plugin:1"].disposition == "assigned" and latest["plugin:1"].note == "new"
    assert latest["plugin:2"].disposition == "false-positive"


def test_entry_to_dict_matches_the_log_line(tmp_path):
    path = tmp_path / "d.jsonl"
    entry = rec(path)
    assert entry.to_dict() == json.loads(path.read_text(encoding="utf-8"))
