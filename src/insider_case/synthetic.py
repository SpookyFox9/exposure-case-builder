"""Seeded synthetic data generator emitting CERT-shaped CSV files.

Everything here is invented: user IDs, PCs and domains (``.example``). Planted
insiders and benign decoys are listed in ``answers.csv`` so detector recall and
false positives can be measured exactly.
"""

from __future__ import annotations

import csv
import random
from datetime import date, datetime, timedelta
from pathlib import Path

DEPARTMENTS = ("Engineering", "Finance", "Sales", "Support")
N_USERS = 50
N_DAYS = 90
START = date(2026, 1, 5)
CORP_DOMAIN = "corp.example"
NORMAL_SITES = ("news.example", "docs.example", "search.example", "wiki.example", "mail.example")
JOB_SITES = ("jobs-board.example", "careers-hub.example")
EXFIL_SITE = "filedrop.example"

SCENARIOS = ("job_site_exfil", "usb_file_copy", "email_exfil")
INSIDERS_PER_SCENARIO = 2
WINDOW_DAYS = 20  # trailing workdays in which insider activity is planted
SOURCE_PREFIX = {"logon": "L", "device": "D", "file": "F", "email": "E", "http": "H"}
LABELS_DIR = "_labels"  # ground truth kept apart from ingestible source files
BENIGN_LEAVERS = 2  # non-insiders with an end_date, so end_date alone is no tell

_HEADERS = {
    "logon": ["id", "date", "user", "pc", "activity"],
    "device": ["id", "date", "user", "pc", "activity"],
    "file": ["id", "date", "user", "pc", "filename"],
    "email": ["id", "date", "user", "pc", "to", "size", "attachment_count"],
    "http": ["id", "date", "user", "pc", "url"],
}


class _Sink:
    """Collects rows per source and assigns stable, unique record IDs."""

    def __init__(self) -> None:
        self.rows: dict[str, list[tuple[datetime, dict[str, object]]]] = {k: [] for k in _HEADERS}

    def add(self, source: str, ts: datetime, **fields: object) -> None:
        self.rows[source].append((ts, fields))

    def write(self, out_dir: Path) -> None:
        for source, headers in _HEADERS.items():
            ordered = sorted(self.rows[source], key=lambda r: (r[0], str(r[1].get("user"))))
            with (out_dir / f"{source}.csv").open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=headers, lineterminator="\n")
                writer.writeheader()
                for n, (ts, fields) in enumerate(ordered, start=1):
                    writer.writerow({"id": f"{SOURCE_PREFIX[source]}-{n:06d}", "date": ts.isoformat(sep=" "), **fields})


def _workdays() -> list[date]:
    days = (START + timedelta(days=i) for i in range(N_DAYS))
    return [d for d in days if d.weekday() < 5]


def _at(day: date, hour: float) -> datetime:
    return datetime.combine(day, datetime.min.time()) + timedelta(hours=hour)


def _baseline_day(rng: random.Random, sink: _Sink, user: str, pc: str, day: date, start: float,
                  ext_email_rate: float = 0.03) -> None:
    sink.add("logon", _at(day, start + rng.uniform(0, 0.5)), user=user, pc=pc, activity="Logon")
    sink.add("logon", _at(day, start + 8.5 + rng.uniform(0, 0.5)), user=user, pc=pc, activity="Logoff")
    for _ in range(rng.randint(3, 8)):
        sink.add("http", _at(day, start + rng.uniform(0.5, 8)), user=user, pc=pc,
                 url=f"https://{rng.choice(NORMAL_SITES)}/page{rng.randint(1, 50)}")
    for _ in range(rng.randint(1, 4)):
        sink.add("email", _at(day, start + rng.uniform(0.5, 8)), user=user, pc=pc,
                 to=f"peer{rng.randint(1, 99)}@{CORP_DOMAIN}", size=rng.randint(800, 6000), attachment_count=0)
    if rng.random() < 0.15:
        sink.add("file", _at(day, start + rng.uniform(1, 7)), user=user, pc=pc,
                 filename=f"report{rng.randint(1, 30)}.docx")
    if rng.random() < ext_email_rate:
        sink.add("email", _at(day, start + rng.uniform(1, 7)), user=user, pc=pc,
                 to=f"partner{rng.randint(1, 9)}@vendor.example", size=rng.randint(5000, 20000),
                 attachment_count=1)


def _offhours_logon(rng: random.Random, sink: _Sink, user: str, pc: str, day: date) -> None:
    hour = rng.choice([22.0, 23.0, 0.5, 1.0, 2.0]) + rng.uniform(0, 0.5)
    sink.add("logon", _at(day, hour), user=user, pc=pc, activity="Logon")


def _plant(rng: random.Random, sink: _Sink, scenario: str, user: str, pc: str, days: list[date]) -> None:
    window = days[-WINDOW_DAYS:]
    for day in window:
        if scenario == "job_site_exfil":
            for _ in range(rng.randint(2, 5)):
                sink.add("http", _at(day, rng.uniform(9, 16)), user=user, pc=pc,
                         url=f"https://{rng.choice(JOB_SITES)}/listing{rng.randint(1, 99)}")
            if rng.random() < 0.4:
                sink.add("http", _at(day, rng.uniform(9, 16)), user=user, pc=pc,
                         url=f"https://{EXFIL_SITE}/upload")
            if rng.random() < 0.5:
                _offhours_logon(rng, sink, user, pc, day)
        elif scenario == "usb_file_copy":
            _offhours_logon(rng, sink, user, pc, day)
            hour = rng.uniform(21, 22.9)  # keeps Disconnect before midnight
            sink.add("device", _at(day, hour), user=user, pc=pc, activity="Connect")
            for k in range(rng.randint(25, 45)):
                sink.add("file", _at(day, hour + 0.01 * (k + 1)), user=user, pc=pc,
                         filename=f"design{rng.randint(1, 500)}.pdf")
            sink.add("device", _at(day, hour + 0.7), user=user, pc=pc, activity="Disconnect")
        elif scenario == "email_exfil":
            for _ in range(rng.randint(1, 3)):
                sink.add("email", _at(day, rng.uniform(9, 17)), user=user, pc=pc,
                         to=f"{user.lower()}.personal@mailbox.example", size=rng.randint(2_000_000, 9_000_000),
                         attachment_count=rng.randint(2, 6))
        else:
            raise ValueError(f"unknown scenario: {scenario}")


def generate(out_dir: str | Path, seed: int = 42) -> None:
    """Write logon/device/file/email/http, roster and answers CSVs into ``out_dir``."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    sink = _Sink()
    days = _workdays()

    users = [f"U{i:04d}" for i in range(1, N_USERS + 1)]
    dept = {u: DEPARTMENTS[i % len(DEPARTMENTS)] for i, u in enumerate(users)}
    pcs = {u: f"PC-{i:04d}" for i, u in enumerate(users, start=1)}
    start_hour = {u: rng.choice([7.5, 8.0, 8.5, 9.0, 9.5]) for u in users}

    # Roles: the first engineer is the benign late-night release engineer; the first
    # sales user makes frequent external-attachment emails (also benign).
    pool = users[:]
    rng.shuffle(pool)
    engineers = [u for u in users if dept[u] == "Engineering"]
    sales = [u for u in users if dept[u] == "Sales"]
    decoy_release, decoy_sales = engineers[0], sales[0]
    candidates = [u for u in pool if u not in (decoy_release, decoy_sales)]
    insiders = {s: candidates[INSIDERS_PER_SCENARIO * i: INSIDERS_PER_SCENARIO * (i + 1)] for i, s in enumerate(SCENARIOS)}
    insider_set = {u for pair in insiders.values() for u in pair}
    benign = [u for u in candidates if u not in insider_set][:BENIGN_LEAVERS]
    leavers = set(insiders["job_site_exfil"]) | set(benign)

    for user in users:
        rate = 0.5 if user == decoy_sales else 0.03
        for day in days:
            _baseline_day(rng, sink, user, pcs[user], day, start_hour[user], ext_email_rate=rate)
        if user == decoy_release:
            for day in days[::4]:
                _offhours_logon(rng, sink, user, pcs[user], day)
    for scenario, pair in insiders.items():
        for user in pair:
            _plant(rng, sink, scenario, user, pcs[user], days)
    sink.write(out)

    last_day = days[-1]
    with (out / "roster.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(["user_id", "role", "department", "pc", "end_date"])
        for user in users:
            leaves = user in leavers
            end = (last_day + timedelta(days=14)).isoformat() if leaves else ""
            role = "Release Engineer" if user == decoy_release else "Staff"
            writer.writerow([user, role, dept[user], pcs[user], end])

    (out / LABELS_DIR).mkdir(exist_ok=True)
    with (out / LABELS_DIR / "answers.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(["user_id", "label", "scenario", "start", "end"])
        window = (days[-WINDOW_DAYS].isoformat(), last_day.isoformat())
        for scenario, pair in insiders.items():
            for user in pair:
                writer.writerow([user, "insider", scenario, *window])
        writer.writerow([decoy_release, "decoy", "late_night_release", days[0].isoformat(), last_day.isoformat()])
        writer.writerow([decoy_sales, "decoy", "frequent_external_attachments", days[0].isoformat(), last_day.isoformat()])
