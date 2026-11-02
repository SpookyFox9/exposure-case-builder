import csv
from pathlib import Path

from insider_case.synthetic import generate

FILES = ["logon.csv", "device.csv", "file.csv", "email.csv", "http.csv", "roster.csv", "_labels/answers.csv"]


def _rows(path: Path):
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def test_writes_all_files(tmp_path):
    generate(tmp_path, seed=7)
    for name in FILES:
        assert (tmp_path / name).is_file(), name


def test_deterministic_for_same_seed(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    generate(a, seed=7)
    generate(b, seed=7)
    for name in FILES:
        assert (a / name).read_bytes() == (b / name).read_bytes(), name


def test_different_seed_differs(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    generate(a, seed=1)
    generate(b, seed=2)
    assert (a / "logon.csv").read_bytes() != (b / "logon.csv").read_bytes()


def test_roster_and_planted_counts(tmp_path):
    generate(tmp_path, seed=7)
    roster = _rows(tmp_path / "roster.csv")
    answers = _rows(tmp_path / "_labels" / "answers.csv")
    assert 45 <= len(roster) <= 55
    assert len({r["department"] for r in roster}) >= 3
    labels = [a["label"] for a in answers]
    assert labels.count("insider") == 6
    assert labels.count("decoy") == 2
    assert len({a["scenario"] for a in answers if a["label"] == "insider"}) == 3
    users = {r["user_id"] for r in roster}
    assert {a["user_id"] for a in answers} <= users


def test_record_ids_unique_per_source(tmp_path):
    generate(tmp_path, seed=7)
    for name in ["logon.csv", "device.csv", "file.csv", "email.csv", "http.csv"]:
        ids = [r["id"] for r in _rows(tmp_path / name)]
        assert ids and len(ids) == len(set(ids)), name


def test_events_reference_roster_users(tmp_path):
    generate(tmp_path, seed=7)
    users = {r["user_id"] for r in _rows(tmp_path / "roster.csv")}
    for name in ["logon.csv", "device.csv", "file.csv", "email.csv", "http.csv"]:
        assert {r["user"] for r in _rows(tmp_path / name)} <= users, name


def test_insider_signals_planted(tmp_path):
    generate(tmp_path, seed=7)
    answers = _rows(tmp_path / "_labels" / "answers.csv")
    device_users = {r["user"] for r in _rows(tmp_path / "device.csv")}
    by_scenario = {}
    for a in answers:
        if a["label"] == "insider":
            by_scenario.setdefault(a["scenario"], set()).add(a["user_id"])
    http_urls = {}
    for r in _rows(tmp_path / "http.csv"):
        http_urls.setdefault(r["user"], []).append(r["url"])
    # job-site scenario: every user in it visits a job board
    job_users = by_scenario["job_site_exfil"]
    assert all(any("jobs" in u or "career" in u for u in http_urls.get(user, [])) for user in job_users)
    # usb scenario: every user in it has a device connect
    usb = by_scenario["usb_file_copy"]
    assert usb <= device_users


def test_email_exfil_and_midnight_and_window(tmp_path):
    generate(tmp_path, seed=7)
    answers = _rows(tmp_path / "_labels" / "answers.csv")
    email_users = {a["user_id"] for a in answers if a["scenario"] == "email_exfil"}
    big = {r["user"] for r in _rows(tmp_path / "email.csv") if int(r["attachment_count"]) >= 2}
    assert email_users <= big
    # Device events stay on a single calendar day per connect/disconnect pair.
    for r in _rows(tmp_path / "device.csv"):
        assert r["date"][11:13] != "00"
    insiders = {a["user_id"] for a in answers if a["label"] == "insider"}
    decoys = {a["user_id"] for a in answers if a["label"] == "decoy"}
    assert insiders.isdisjoint(decoys)
    end = max(a["end"] for a in answers)
    assert all(r["date"][:10] <= end for r in _rows(tmp_path / "device.csv"))


def test_end_date_is_not_a_tell(tmp_path):
    generate(tmp_path, seed=7)
    answers = _rows(tmp_path / "_labels" / "answers.csv")
    insiders = {a["user_id"] for a in answers if a["label"] == "insider"}
    leavers = {r["user_id"] for r in _rows(tmp_path / "roster.csv") if r["end_date"]}
    assert leavers - insiders
