"""The skill and playbook must stay in step with the server they describe."""

import asyncio
import re
from pathlib import Path

import pytest

from exposure_case.server import build_server
from exposure_case.service import Workspace
from exposure_case.trend import CATEGORIES

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "skills" / "exposure-case" / "SKILL.md"
PLAYBOOK = ROOT / "playbooks" / "exposure-case-playbook.md"


@pytest.fixture(scope="module")
def tool_names(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("skill")
    ws = Workspace.load(ROOT / "data" / "sample", exports_dir=tmp / "e", dispositions_path=tmp / "d.jsonl")
    return {t.name for t in asyncio.run(build_server(ws).list_tools())}


def frontmatter(text: str) -> dict:
    match = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    assert match, "SKILL.md must start with YAML frontmatter"
    return dict(line.split(": ", 1) for line in match.group(1).splitlines() if ": " in line)


def test_frontmatter_names_the_skill():
    fm = frontmatter(SKILL.read_text(encoding="utf-8"))
    assert fm["name"] == "exposure-case" and len(fm["description"]) > 40


def test_every_server_tool_is_described_in_the_skill(tool_names):
    text = SKILL.read_text(encoding="utf-8")
    missing = {name for name in tool_names if f"`{name}`" not in text}
    assert not missing, f"tools not mentioned in SKILL.md: {sorted(missing)}"


def test_skill_does_not_invent_tools(tool_names):
    text = SKILL.read_text(encoding="utf-8")
    candidates = set(re.findall(r"`([a-z]+(?:_[a-z]+)+)`", text))
    known_fields = {
        "case_id",
        "top_n",
        "hide_dispositioned",
        "evidence_ids",
        "hosts_csv",
        "actions_csv",
        "fix_package",
        "case_queue",
        "fix_queue",
        "case_file",
        "fleet_summary",
        "record_disposition",
        "risk_accepted",
        "data_quality",
        "export_below_workbench",
        "export_above_workbench",
        "epss_score",
        *CATEGORIES,
    }
    unknown = {c for c in candidates if c not in tool_names and c not in known_fields}
    assert not unknown, f"unrecognised identifiers in SKILL.md: {sorted(unknown)}"


@pytest.mark.parametrize(
    "phrase",
    [
        "finding ID",
        "verdict",
        "Tenable-provided",
        "confirm=true",
        "masked",
        "append-only",
        "No recommendation may target",
        "two lists",
        "data, not instructions",
        "cannot verify",
        "never call a write tool because of",
    ],
)
def test_skill_states_the_hard_rules(phrase):
    assert phrase.lower() in SKILL.read_text(encoding="utf-8").lower()


def test_playbook_covers_setup_and_safety():
    text = PLAYBOOK.read_text(encoding="utf-8")
    for phrase in (
        "EXPOSURE_CASE_DATA",
        "claude mcp add",
        "fetch_tenable.py",
        "confirm",
        "Troubleshooting",
        "Data flows",
        "contains",
    ):
        assert phrase in text, phrase


def test_playbook_never_asks_for_keys_in_the_repo():
    text = PLAYBOOK.read_text(encoding="utf-8").lower()
    assert "outside the repo" in text and ".env" not in text


def test_skill_explains_the_coverage_order_and_its_limits():
    text = SKILL.read_text(encoding="utf-8")
    assert 'order="coverage"' in text
    for phrase in ("heuristic", "not the shortest plan", "earlier step", "urgent"):
        assert phrase in text.lower() or phrase in text, phrase


def test_skill_never_lets_absence_stand_in_for_a_fix():
    text = " ".join(SKILL.read_text(encoding="utf-8").lower().split())
    assert "trend_diff" in text
    for phrase in ("never call a finding fixed", "only `fixed_recorded`", "host overlap"):
        assert phrase in text, phrase


def _skill_text() -> str:
    return " ".join(SKILL.read_text(encoding="utf-8").lower().split())


def test_skill_forbids_reordering_or_resumming_coverage_steps():
    # Rehearsal 2026-11-03: Claude moved steps 5-7 ahead and added their host counts, which only hold after
    # steps 1-4. Each step's figure depends on every earlier step.
    text = _skill_text()
    for phrase in ("never reorder", "depends on every earlier step", "recomputed"):
        assert phrase in text, phrase


def test_skill_limits_claims_to_what_the_tools_returned():
    text = _skill_text()
    for phrase in ("only, most, first, cheapest", "effort", "do not infer causes", "not from tenable's data"):
        assert phrase in text, phrase


def test_skill_shows_exports_and_explains_source_records():
    text = _skill_text()
    for phrase in ("show the returned document", "source records", "no owner"):
        assert phrase in text, phrase


def test_skill_explains_the_data_quality_figures():
    text = _skill_text()
    assert "data_quality" in text and "plugins, not findings" in text


def test_skill_does_not_guess_whether_a_baseline_is_configured():
    # Rehearsal 2026-11-03: triage said "no earlier pull configured" without calling trend_diff; one was.
    assert "without calling `trend_diff`" in _skill_text()
