"""JSON-ready answers for the ``trend_diff`` tool: a summary, or one page of one category.

Rows carry ids and facts only. No plugin name, solution or hostname appears. The ids themselves come from the
export, so they are treated as untrusted text: reduced to one line, stripped of invisible characters and capped.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .text_safety import single_line
from .trend import FindingChange, TrendDiff

MAX_ID_CHARS = 120  # ids come from the export; anything longer is not a real id

TREND_NOTE = (
    "A finding that is not present in the later export is NOT reported as fixed: Tenable recorded no fix. The host "
    "may not have been scanned, may have been removed, or the scan scope may have changed; not_seen_rescanned only "
    "means the host has newer observations. newly_visible are older findings the baseline did not include (coverage), "
    "not new risk. Counts cover active, non-informational findings; read the host overlap before any count. Whether "
    "Tenable finding ids are stable between pulls is not documented; id_reuse and possible_rekeys show any sign "
    "they are not."
)


NO_BASELINE_NOTE = (
    "No baseline is configured. Set EXPOSURE_CASE_BASELINE to a saved earlier export directory (an absolute path) "
    "and restart the server to compare pulls."
)


def _clean(value: object) -> str:
    """Ids come from the export, so they are untrusted text: one line, no invisible characters, capped."""
    text = single_line(value)
    return text if len(text) <= MAX_ID_CHARS else text[:MAX_ID_CHARS] + "…"


def _row(change: FindingChange) -> dict[str, Any]:
    return {key: _clean(value) if isinstance(value, str) else value for key, value in asdict(change).items()}


@dataclass(frozen=True)
class TrendReport:
    """A computed diff with the baseline's notes, ready to answer the tool."""

    diff: TrendDiff
    notes: tuple[str, ...]
    synthetic: bool

    def _hosts(self) -> dict[str, int]:
        d = self.diff
        return {
            "baseline": d.hosts_baseline,
            "current": d.hosts_current,
            "in_both": d.hosts_in_both,
            "only_baseline": d.hosts_only_baseline,
            "only_current": d.hosts_only_current,
        }

    def summary(self) -> dict[str, Any]:
        """Counts per category with the host overlap, data-quality counters and the baseline's notes."""
        d = self.diff
        return {
            "configured": True,
            "synthetic": self.synthetic,
            "baseline_as_of": d.baseline_as_of.isoformat(),
            "current_as_of": d.current_as_of.isoformat(),
            "hosts": self._hosts(),
            "findings": d.counts,
            "data_quality": {"id_reuse": d.id_reuse, "possible_rekeys": d.possible_rekeys},
            "notes": list(self.notes),
            "note": TREND_NOTE,
        }

    def page(self, category: str, limit: int, offset: int) -> dict[str, Any]:
        """One page of one category; the host overlap and notes travel with it so no page is read without them."""
        rows = [c for c in self.diff.changes if c.category == category]
        return {
            "configured": True,
            "synthetic": self.synthetic,
            "category": category,
            "hosts": self._hosts(),
            "notes": list(self.notes),
            "total": len(rows),
            "offset": offset,
            "limit": limit,
            "rows": [_row(c) for c in rows[offset : offset + limit]],
            "note": TREND_NOTE,
        }
