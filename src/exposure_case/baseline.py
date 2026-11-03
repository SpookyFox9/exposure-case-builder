"""Load and check the previous pull that the trend diff compares against.

The baseline is a saved export directory named once at startup (``EXPOSURE_CASE_BASELINE``). No tool takes a path.
It is read with the same size limits and validation as the current export. It is refused if it is the data
directory itself, if it is empty, if its newest observation is later than the current export's, or if no host
appears in both pulls. Low host overlap and an identical timestamp are allowed but reported, because they change
what a comparison can mean.

A baseline directory containing a file named ``SYNTHETIC`` is reported as synthetic wherever its results appear, so
a demo built from the sample is never mistaken for a real earlier pull.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .ingest import FindingRecord, IngestError, load_findings

SYNTHETIC_MARKER = "SYNTHETIC"
SYNTHETIC_SCAN_PREFIX = (
    "synthetic-"  # scan ids of a generated baseline start with this, so deleting the file is not enough
)
MIN_HOST_OVERLAP = 0.5  # shared hosts as a share of all hosts seen in either pull


class BaselineError(ValueError):
    """The baseline cannot be used; the message says why."""


@dataclass(frozen=True)
class Baseline:
    records: tuple[FindingRecord, ...]
    notes: tuple[str, ...]
    synthetic: bool


def _read(path: Path, data_dir: Path) -> tuple[FindingRecord, ...]:
    if not path.is_dir():
        raise BaselineError("baseline directory not found")
    if path.resolve() == data_dir.resolve() or (path / "chunks").resolve() == (data_dir / "chunks").resolve():
        raise BaselineError("baseline is the same directory as the current export")
    try:
        records = load_findings(path)
    except IngestError as exc:
        raise BaselineError(f"cannot load the baseline: {exc}") from None
    if not records:
        raise BaselineError("baseline export is empty")
    if all(r.severity == "info" for r in records):
        raise BaselineError("baseline has no non-informational findings, so there is nothing to compare")
    return records


def _timing_notes(records: Sequence[FindingRecord], current: Sequence[FindingRecord]) -> tuple[str, ...]:
    if not current:
        raise BaselineError("the current export is empty, so there is nothing to compare the baseline with")
    baseline_as_of = max(r.last_found for r in records)
    current_as_of = max(r.last_found for r in current)
    if baseline_as_of > current_as_of:
        raise BaselineError("baseline is newer than the current export; swap them or fix the path")
    if baseline_as_of == current_as_of:
        return ("baseline and current have the same newest observation: this is likely the same pull",)
    return ()


def _overlap_notes(records: Sequence[FindingRecord], current: Sequence[FindingRecord]) -> tuple[str, ...]:
    before, now = {r.asset_uuid for r in records}, {r.asset_uuid for r in current}
    shared = len(before & now)
    if not shared:
        raise BaselineError(
            "baseline shares no host with the current export: this does not look like the same environment"
        )
    share = shared / len(before | now)
    if share < MIN_HOST_OVERLAP:
        message = (
            f"host overlap is low ({shared} shared of {len(before | now)} hosts seen in either pull): "
            "most changes may reflect scan scope, not the environment"
        )
        return (message,)
    return ()


def load_baseline(path: Path, data_dir: Path, current: Sequence[FindingRecord]) -> Baseline:
    """Load and validate the baseline against the current export; raise ``BaselineError`` if unusable."""
    records = _read(Path(path), Path(data_dir))
    notes = (*_timing_notes(records, current), *_overlap_notes(records, current))
    synthetic = (Path(path) / SYNTHETIC_MARKER).is_file() or any(
        r.scan_uuid.startswith(SYNTHETIC_SCAN_PREFIX) for r in records
    )
    if synthetic:
        notes = ("this baseline is synthetic (generated for a demonstration), not a real earlier pull", *notes)
    return Baseline(records=records, notes=notes, synthetic=synthetic)
