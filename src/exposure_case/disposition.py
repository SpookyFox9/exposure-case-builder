"""The analyst's decision, recorded in a local append-only JSONL log.

This is the only thing in the tool that records a human judgement, and it never changes any Tenable
data or any other system. Entries are only ever appended; reading takes the latest entry per item.
The analyst name is free text (there is no authentication), so treat the log as a worklog, not an
audit trail.
"""

from __future__ import annotations

import json
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DISPOSITIONS = ("assigned", "risk-accepted", "false-positive", "needs-info")
KINDS = ("case", "fix_package")
MAX_NOTE_CHARS = 2000
MAX_ANALYST_CHARS = 80
MAX_ITEM_ID_CHARS = 200
_STRIPPED = frozenset({"Cc", "Cf", "Zl", "Zp"})


class DispositionError(ValueError):
    """Raised when a disposition cannot be recorded or read."""


@dataclass(frozen=True)
class Disposition:
    item_id: str
    kind: str
    analyst: str
    disposition: str
    note: str
    recorded_at: datetime
    data_as_of: datetime

    def to_dict(self) -> dict:
        return {
            "item_id": self.item_id, "kind": self.kind, "analyst": self.analyst, "disposition": self.disposition,
            "note": self.note, "recorded_at": self.recorded_at.isoformat(), "data_as_of": self.data_as_of.isoformat(),
        }


def _clean(value: str) -> str:
    text = value.replace("\t", " ").replace("\n", " ").replace("\r", " ")
    return " ".join("".join(ch for ch in text if unicodedata.category(ch) not in _STRIPPED).split())


def _aware(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise DispositionError(f"{name} must be a timezone-aware datetime")
    return value


def _now() -> datetime:
    return datetime.now(timezone.utc)


def record_disposition(
    path: str | Path,
    *,
    item_id: str,
    kind: str,
    analyst: str,
    disposition: str,
    note: str,
    confirm: bool,
    data_as_of: datetime,
    clock: Callable[[], datetime] = _now,
) -> Disposition:
    """Validate, then append exactly one line. Nothing is written unless every check passes."""
    if confirm is not True:
        raise DispositionError("recording a disposition requires confirm=true (the analyst's explicit approval)")
    if disposition not in DISPOSITIONS:
        raise DispositionError(f"disposition must be one of {', '.join(DISPOSITIONS)}")
    if kind not in KINDS:
        raise DispositionError(f"kind must be one of {', '.join(KINDS)}")
    if not isinstance(item_id, str) or not item_id or len(item_id) > MAX_ITEM_ID_CHARS or _clean(item_id) != item_id:
        raise DispositionError("item_id is empty, too long or contains control characters")
    analyst_clean = _clean(analyst) if isinstance(analyst, str) else ""
    if not analyst_clean or len(analyst_clean) > MAX_ANALYST_CHARS:
        raise DispositionError(f"analyst is required and at most {MAX_ANALYST_CHARS} characters")
    if not isinstance(note, str) or len(note) > MAX_NOTE_CHARS:
        raise DispositionError(f"note must be text of at most {MAX_NOTE_CHARS} characters")
    entry = Disposition(item_id, kind, analyst_clean, disposition, _clean(note),
                        _aware(clock(), "clock()"), _aware(data_as_of, "data_as_of"))

    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(entry.to_dict(), sort_keys=True, ensure_ascii=False) + "\n")
    except OSError as exc:
        raise DispositionError(f"cannot write the disposition log: {type(exc).__name__}") from None
    return entry


def _parse(line: str, number: int) -> Disposition:
    try:
        data = json.loads(line)
        return Disposition(
            item_id=data["item_id"], kind=data["kind"], analyst=data["analyst"], disposition=data["disposition"],
            note=data["note"], recorded_at=datetime.fromisoformat(data["recorded_at"]),
            data_as_of=datetime.fromisoformat(data["data_as_of"]),
        )
    except (ValueError, KeyError, TypeError):
        raise DispositionError(f"corrupt disposition log entry at line {number}") from None


def read_dispositions(path: str | Path) -> tuple[Disposition, ...]:
    """All entries in file order; a missing file means none have been recorded."""
    target = Path(path)
    if not target.exists():
        return ()
    try:
        text = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DispositionError(f"cannot read the disposition log: {type(exc).__name__}") from None
    return tuple(_parse(line, i) for i, line in enumerate(text.splitlines(), start=1) if line.strip())


def latest_by_item(entries: tuple[Disposition, ...]) -> dict[str, Disposition]:
    """The most recent entry for each item id (later lines win)."""
    return {e.item_id: e for e in entries}
