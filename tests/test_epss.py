"""EPSS is shown beside KEV and VPR as its own signal, never folded into the score.

FIRST: "EPSS is not a complete risk score" and an EPSS score should not be multiplied into a combined risk number.
Research checklist D3 (2026-11-03): show it as a separate column or say why it is left out.
"""

from pathlib import Path

import pytest

from exposure_case.ingest import load_findings
from exposure_case.service import Workspace

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample"
SHELLSHOCK = "plugin:77823"

pytestmark = pytest.mark.integration


@pytest.fixture
def ws(tmp_path):
    return Workspace.load(SAMPLE, exports_dir=tmp_path / "e", dispositions_path=tmp_path / "d.jsonl")


def test_case_file_shows_the_highest_epss_for_each_vulnerability(ws):
    expected = max(r.epss_score for r in load_findings(SAMPLE) if r.plugin_id == 77823 and r.epss_score is not None)
    vuln = ws.case_file(SHELLSHOCK)["vulnerabilities"][0]
    assert vuln["plugin_id"] == 77823 and vuln["epss_score"] == expected


def test_epss_is_not_a_score_component(ws):
    names = {c["name"] for c in ws.case_file(SHELLSHOCK)["score"]["components"]}
    assert not any("epss" in n for n in names)


def test_markdown_case_export_has_an_epss_column(ws):
    text = ws.export(SHELLSHOCK, "markdown")["content"]
    assert "| EPSS % |" in text


@pytest.mark.unit
def test_epss_takes_the_highest_value_and_ignores_missing_ones():
    from test_cluster import finding

    from exposure_case.case import vulnerability_lines

    lines = vulnerability_lines(
        [
            finding("a", plugin=5, epss_score=0.2),
            finding("b", plugin=5, asset="a2"),
            finding("c", plugin=5, epss_score=0.7),
        ]
    )
    assert lines[0].epss_score == 0.7
    assert vulnerability_lines([finding("d", plugin=6)])[0].epss_score is None


def test_markdown_row_carries_the_epss_value(ws):
    vuln = ws.case_file(SHELLSHOCK)["vulnerabilities"][0]
    text = ws.export(SHELLSHOCK, "markdown")["content"]
    assert f"| {vuln['epss_score']} |" in text
