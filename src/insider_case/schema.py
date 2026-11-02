"""Immutable core types shared by the engine."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Evidence:
    """A pointer to the source record that triggered a finding."""

    source: str
    record_id: str

    def to_dict(self) -> dict[str, str]:
        return {"source": self.source, "record_id": self.record_id}


@dataclass(frozen=True)
class Event:
    """One normalized record from any source (logon, device, file, email, http)."""

    source: str
    record_id: str
    ts: datetime
    user: str
    pc: str
    summary: str


@dataclass(frozen=True)
class Finding:
    """A detector result. Evidence is mandatory: no finding without source records."""

    id: str
    detector: str
    user: str
    date: str
    score: float
    rationale: str
    evidence: tuple[Evidence, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", tuple(self.evidence))
        if not math.isfinite(self.score):
            raise ValueError("score must be a finite number")
        if not self.evidence:
            raise ValueError("a Finding requires at least one evidence record")
        if any(not ev.record_id.strip() or not ev.source.strip() for ev in self.evidence):
            raise ValueError("every evidence item needs a non-empty source and record_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "detector": self.detector,
            "user": self.user,
            "date": self.date,
            "score": self.score,
            "rationale": self.rationale,
            "evidence": [ev.to_dict() for ev in self.evidence],
        }
