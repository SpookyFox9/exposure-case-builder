"""The quality gates must stay wired into the commit hook and CI, and private rule files must stay untracked."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CHECK_ALL = ROOT / "scripts" / "check_all.sh"
HOOK = ROOT / ".githooks" / "pre-commit"
CI = ROOT / ".github" / "workflows" / "ci.yml"
CLAUDE_MD = ROOT / "CLAUDE.md"

GATES = [
    "ruff check",
    "black --check",
    "mypy",
    "bandit",
    "check_standards.py",
    "coverage run",
    "coverage report",
]


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_one_script_runs_every_gate():
    text = read(CHECK_ALL)
    assert not [g for g in GATES if g not in text], "a quality gate is missing from scripts/check_all.sh"
    assert text.startswith("#!/bin/sh") and "set -e" in text


def test_the_commit_hook_scans_for_secrets_and_runs_every_gate():
    text = read(HOOK)
    assert "gitleaks" in text and "check_all.sh" in text
    assert "exit 1" in text  # fails closed when a tool is missing


def test_ci_runs_the_same_script_on_oldest_and_newest_python():
    text = read(CI)
    assert "scripts/check_all.sh" in text
    assert '"3.10"' in text and re.search(r'"3\.1[2-9]"', text)


def test_ci_has_least_privilege_and_pins_every_action_to_a_commit():
    text = read(CI)
    assert re.search(r"permissions:\s*\n\s+contents: read", text)
    uses = re.findall(r"uses:\s*(\S+)", text)
    assert uses, "expected at least one action"
    for ref in uses:
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", ref), f"action not pinned to a full commit hash: {ref}"


def test_ci_does_not_expose_secrets_or_use_dangerous_triggers():
    text = read(CI)
    assert "pull_request_target" not in text
    assert not re.search(r"\$\{\{\s*secrets\.", text), "the workflow must not read repository secrets"


def test_claude_md_states_the_engineering_standards():
    text = read(CLAUDE_MD)
    for phrase in (
        "Engineering standards",
        "check_all.sh",
        "core.hooksPath",
        "RED",
        "security-reviewer",
        "docs/PRIOR_ART.md",
    ):
        assert phrase in text, phrase


def test_the_private_rule_files_are_ignored_and_untracked():
    assert ".claude/rules/" in read(ROOT / ".gitignore")
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    tracked = subprocess.run(
        ["git", "ls-files", ".claude"], cwd=ROOT, capture_output=True, text=True, check=False
    ).stdout
    assert tracked.strip() == "", f"tracked files under .claude: {tracked}"


def test_docs_referenced_from_claude_md_and_readme_exist():
    refs = set()
    for name in ("CLAUDE.md", "README.md"):
        refs |= set(re.findall(r"docs/[\w./-]+\.md", read(ROOT / name)))
    assert refs, "expected the entry-point docs to point at docs/"
    missing = sorted(r for r in refs if not (ROOT / r).is_file())
    assert not missing, f"referenced docs do not exist: {missing}"
