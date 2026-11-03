"""fleet_summary's data_quality block: labelled so a model cannot read it as 'half the findings are wrong'."""

import shutil
from pathlib import Path

import pytest

from exposure_case.reconcile import Mismatch, Reconciliation, quality_summary
from exposure_case.service import Workspace

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample"

pytestmark = pytest.mark.unit


def _rec(*mismatches: Mismatch) -> Reconciliation:
    return Reconciliation(
        compared=10, exact=10 - len(mismatches), instances_only=0, not_in_workbench=1, mismatches=tuple(mismatches)
    )


def test_counts_are_plugins_with_both_directions_and_the_rest_straddling():
    below = Mismatch(1, export_assets=2, export_findings=3, workbench_count=5)
    above = Mismatch(2, export_assets=6, export_findings=8, workbench_count=4)
    straddle = Mismatch(3, export_assets=5, export_findings=9, workbench_count=7)
    q = quality_summary(_rec(below, above, straddle))
    assert q["compared_unit"] == "plugins"
    assert (q["compared"], q["exact"], q["mismatch_count"], q["not_in_workbench"]) == (10, 7, 3, 1)
    assert (q["export_below_workbench"], q["export_above_workbench"]) == (1, 1)
    assert "export_below_workbench" in q["note"] and "export_above_workbench" in q["note"]
    assert "unverified" in q["note"] and "not that its findings are wrong" in q["note"]


def test_no_mismatches_is_a_clean_summary():
    q = quality_summary(_rec())
    assert q["mismatch_count"] == 0 and q["export_below_workbench"] == q["export_above_workbench"] == 0


@pytest.mark.integration
def test_sample_reports_direction_counts_within_the_mismatches(tmp_path):
    ws = Workspace.load(SAMPLE, exports_dir=tmp_path / "e", dispositions_path=tmp_path / "d.jsonl")
    q = ws.fleet_summary()["data_quality"]
    assert q["export_below_workbench"] + q["export_above_workbench"] <= q["mismatch_count"]


@pytest.mark.integration
def test_no_plugins_file_means_no_data_quality_block(tmp_path):
    data = tmp_path / "data"
    shutil.copytree(SAMPLE / "chunks", data / "chunks")
    ws = Workspace.load(data, exports_dir=tmp_path / "e", dispositions_path=tmp_path / "d.jsonl")
    assert "data_quality" not in ws.fleet_summary()
