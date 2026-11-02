"""The one core type every number in the tool is traced back through."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Evidence:
    """A pointer to a source record (a Tenable finding) that supports a case, package or timeline entry."""

    source: str
    record_id: str

    def __post_init__(self) -> None:
        for value in (self.source, self.record_id):
            if not isinstance(value, str) or not value.strip():
                raise ValueError("evidence needs a non-empty source and record_id")

    def to_dict(self) -> dict[str, str]:
        return {"source": self.source, "record_id": self.record_id}
