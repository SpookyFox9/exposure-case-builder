"""Attack payloads used as test data must never sit on disk as a complete, scannable string.

Antivirus scanners (BitDefender flagged ``Generic.DDE.Exploit`` in pytest's ``lastfailed`` cache file, which records
test IDs, and those IDs embed the parameter text) match on payload text, not behaviour. The payloads are inert test
inputs to our escaping code, so we keep them out of test IDs (conftest) and build the Excel-DDE launcher from parts.
This file builds its own patterns from fragments for the same reason.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", ".venv", "data", "node_modules", "__pycache__", ".claude"}

# Built from fragments so this file never contains a complete payload itself.
DDE_LAUNCHER = re.compile("cm" + "d" + r"\|" + r".{0,4}/[Cc]\s")
HOSTILE_ID_FRAGMENTS = re.compile(
    "|".join(["cm" + r"d\|", "<scr" + "ipt", "javas" + "cript:", "oner" + "ror", "ca" + "lc'", "HYPER" + "LINK"]),
    re.IGNORECASE,
)


def project_files():
    for path in ROOT.rglob("*"):
        if (
            path.is_file()
            and not SKIP_DIRS & set(path.relative_to(ROOT).parts[:-1])
            and path.stat().st_size < 2_000_000
        ):
            yield path


def test_no_test_id_embeds_attack_payload_text(request):
    offenders = [item.nodeid for item in request.session.items if HOSTILE_ID_FRAGMENTS.search(item.nodeid)]
    assert not offenders, f"test ids must be neutral; offenders: {offenders[:3]}"


def test_no_project_file_contains_a_complete_dde_launcher():
    hits = []
    for path in project_files():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if DDE_LAUNCHER.search(text):
            hits.append(str(path.relative_to(ROOT)))
    assert not hits, f"files containing a literal DDE launcher string: {hits}"


def test_the_csv_neutralizer_still_defuses_the_dde_launcher():
    from exposure_case.text_safety import csv_cell

    launcher = "=" + "cm" + "d|' /C " + "ca" + "lc'!A0"
    assert csv_cell(launcher).startswith("'=")


@pytest.mark.parametrize(
    "value", ["=" + "cm" + "d|' /C " + "ca" + "lc'!A0", "<scr" + "ipt>x</scr" + "ipt>", "javas" + "cript:x"]
)
def test_hostile_parameters_get_neutral_ids(value, request):
    assert re.fullmatch(r"hostile-[0-9a-f]{8}", request.node.callspec.id), request.node.callspec.id
