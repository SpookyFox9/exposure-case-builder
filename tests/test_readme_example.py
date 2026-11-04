"""The README's "What you get" excerpt must stay exactly what the tool returns for the committed sample."""

from __future__ import annotations

import re
from pathlib import Path

from exposure_case.service import Workspace

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "fix:openbsd-openssh:patch"


def _readme_excerpt() -> list[str]:
    text = (ROOT / "README.md").read_text("utf-8")
    section = text.split("## What you get", 1)[1].split("\n## Prerequisites", 1)[0]
    match = re.search(r"```markdown\n(.*?)\n```", section, re.DOTALL)
    assert match, "the What you get section needs a ```markdown excerpt"
    return match.group(1).splitlines()


def test_readme_excerpt_is_the_start_of_the_real_export(tmp_path: Path) -> None:
    ws = Workspace.load(ROOT / "data" / "sample", exports_dir=tmp_path / "x", dispositions_path=tmp_path / "d.jsonl")
    exported = ws.export(PACKAGE, format="markdown")["content"].splitlines()
    excerpt = _readme_excerpt()
    assert excerpt == exported[: len(excerpt)]


def test_readme_figures_match_the_sample(tmp_path: Path) -> None:
    ws = Workspace.load(ROOT / "data" / "sample", exports_dir=tmp_path / "x", dispositions_path=tmp_path / "d.jsonl")
    summary = ws.fleet_summary()
    top = ws.fix_queue(top_n=1)["items"][0]
    section = (ROOT / "README.md").read_text("utf-8").split("## What you get", 1)[1].split("## Prerequisites", 1)[0]
    expected = (
        f"{summary['hosts']} hosts",
        f"{summary['active_findings']:,} (",
        f"{summary['by_severity']['critical']} critical",
        f"{summary['kev_findings']} on the CISA KEV list",
        f"{summary['cases']['total']}: {summary['cases']['threats']} single-vulnerability threats",
        f"{summary['fix_packages']['total']}: {summary['fix_packages']['patch']} patches",
        f"{top['actions']} Tenable actions, {top['findings']} findings, {top['hosts']} hosts, score {top['score']}",
    )
    for phrase in expected:
        assert phrase in section, phrase
    assert top["package_id"] == PACKAGE
