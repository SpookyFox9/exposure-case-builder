"""Immutable core types shared by the engine."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Evidence:
    """A pointer to the source record that triggered a finding."""

    source: str
    record_id: str

    def to_dict(self) -> dict[str, str]:
        return {"source": self.source, "record_id": self.record_id}


@dataclass(frozen=True)
class Finding:
    """A detector result about one subject (a cluster, an asset). Evidence is mandatory."""

    id: str
    detector: str
    subject: str
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
            "subject": self.subject,
            "score": self.score,
            "rationale": self.rationale,
            "evidence": [ev.to_dict() for ev in self.evidence],
        }
