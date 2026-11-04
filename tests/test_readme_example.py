"""The README's "What you get" section must stay exactly what the tool returns for the committed sample."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from exposure_case.service import Workspace

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "fix:openbsd-openssh:patch"
MIN_EXCERPT_LINES = 10
NUMBER_WORDS = {6: "six", 10: "ten"}
OUT_OF_STEP = "README 'What you get' is out of step with the sample"


@pytest.fixture(scope="module")
def workspace(tmp_path_factory: pytest.TempPathFactory) -> Workspace:
    out = tmp_path_factory.mktemp("readme")
    return Workspace.load(ROOT / "data" / "sample", exports_dir=out / "x", dispositions_path=out / "d.jsonl")


@pytest.fixture(scope="module")
def section() -> str:
    lines = (ROOT / "README.md").read_text("utf-8").splitlines()
    assert "## What you get" in lines, "README.md needs a '## What you get' section"
    body: list[str] = []
    in_fence = False
    for line in lines[lines.index("## What you get") + 1 :]:
        if line.startswith("## ") and not in_fence:
            break  # the next README section; headings inside the excerpt's fence belong to the export
        if line.startswith("```"):
            in_fence = not in_fence
        body = [*body, line]
    return "\n".join(body)


def _excerpt(section: str) -> list[str]:
    match = re.search(r"```markdown\n(.*?)\n```", section, re.DOTALL)
    assert match, "the What you get section needs a ```markdown excerpt"
    return match.group(1).splitlines()


def _prose(section: str) -> str:
    """The section without its excerpt, so a figure cannot match text inside the export."""
    return re.sub(r"```markdown\n.*?\n```", "", section, flags=re.DOTALL)


def test_readme_excerpt_is_the_start_of_the_real_export(workspace: Workspace, section: str) -> None:
    exported = workspace.export(PACKAGE, format="markdown")["content"].splitlines()
    excerpt = _excerpt(section)
    assert len(excerpt) >= MIN_EXCERPT_LINES, f"the excerpt is too short to show the action table: {len(excerpt)}"
    assert len(exported) >= len(excerpt), "the excerpt is longer than the export"
    for number, (shown, real) in enumerate(zip(excerpt, exported[: len(excerpt)], strict=True), start=1):
        assert shown == real, f"{OUT_OF_STEP}: excerpt line {number} is {shown!r}, the export has {real!r}"


def _expected_lines(summary: dict[str, Any], top: dict[str, Any], shown_actions: int) -> tuple[str, ...]:
    severity, cases, packages = summary["by_severity"], summary["cases"], summary["fix_packages"]
    return (
        f"On the committed sample ({summary['hosts']} hosts, {summary['findings_total']:,} findings of fake,",
        (
            f"| Active findings | {summary['active_findings']:,} ({severity['critical']} critical,"
            f" {severity['high']} high; {summary['kev_findings']} on the CISA KEV list) |"
        ),
        (
            f"| Cases | {cases['total']}: {cases['threats']} single-vulnerability threats and"
            f" {cases['backlogs']} patch-family backlog |"
        ),
        (
            f"| Fix packages | {packages['total']}: {packages['patch']} patches and"
            f" {packages['configuration']} configuration changes |"
        ),
        (
            f"| Top fix package | OpenSSH (patch): {top['actions']} Tenable actions, {top['findings']} findings,"
            f" {top['hosts']} hosts, score {top['score']} |"
        ),
        f"continues with {NUMBER_WORDS[top['actions'] - shown_actions]} more rows",
        f"across all {NUMBER_WORDS[top['actions']]},",
    )


def test_readme_figures_match_the_sample(workspace: Workspace, section: str) -> None:
    top = workspace.fix_queue(top_n=1)["items"][0]
    assert top["package_id"] == PACKAGE, f"{OUT_OF_STEP}: the top fix package is now {top['package_id']}"
    shown_actions = sum(1 for line in _excerpt(section) if line.startswith("| Upgrade to OpenSSH"))
    prose = _prose(section)
    for line in _expected_lines(workspace.fleet_summary(), top, shown_actions):
        assert line in prose, f"{OUT_OF_STEP}: expected {line!r}"
