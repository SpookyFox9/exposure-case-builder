"""Every list a tool returns is capped, with a *_total beside it, so one call cannot flood the model's context.

Found 2026-11-03 on the full competition export (19,437 findings): fix_package returned ~190,000 characters
(4,919 CVEs, 1,516 advisories, 1,516 plugin ids) and case_file ~127,000 (every finding id in every timeline
entry). The committed sample is too small to show it, so the caps are lowered here to exercise them.
"""

import json
from pathlib import Path

import pytest

from exposure_case import service
from exposure_case.service import Workspace

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample"
OPENSSH = "fix:openbsd-openssh:patch"
SHELLSHOCK = "plugin:77823"

pytestmark = pytest.mark.integration


@pytest.fixture
def ws(tmp_path):
    return Workspace.load(SAMPLE, exports_dir=tmp_path / "e", dispositions_path=tmp_path / "d.jsonl")


def test_fix_package_caps_cves_advisories_and_plugin_ids(ws, monkeypatch):
    monkeypatch.setattr(service, "MAX_REFERENCES", 3)
    full = ws._package_view(OPENSSH).to_dict(25)["package"]
    package = ws.fix_package(OPENSSH)["package"]
    for key in ("cves", "advisories", "plugin_ids"):
        assert package[key] == full[key][:3], key
        assert package[f"{key}_total"] == len(full[key]) > 3, key


def test_default_reference_cap_keeps_14_advisories_and_truncates_29_cves(ws):
    package = ws.fix_package(OPENSSH)["package"]
    assert package["advisories_total"] == len(package["advisories"]) == 14
    assert package["cves_total"] == 29 and len(package["cves"]) == service.MAX_REFERENCES


def test_case_file_caps_the_evidence_inside_each_timeline_entry(ws, monkeypatch):
    monkeypatch.setattr(service, "MAX_EVENT_EVIDENCE", 2)
    timeline = ws.case_file(SHELLSHOCK)["timeline"]
    first = next(e for e in timeline if e["count"] > 2)
    assert len(first["evidence"]) == 2 and first["evidence_total"] == first["count"]
    assert all(len(e["evidence"]) <= 2 and e["evidence_total"] >= len(e["evidence"]) for e in timeline)


def test_fix_package_shortens_long_tenable_text(ws, monkeypatch):
    # Security review: the item caps bound how many strings, not how long; each can be 4 KB of untrusted text.
    monkeypatch.setattr(service, "MAX_SOLUTION_CHARS", 12)
    package = ws.fix_package(OPENSSH)["package"]
    assert all(len(a) <= 13 for a in package["advisories"])  # 12 plus the ellipsis
    assert all(len(a["solution"]) <= 13 for a in package["actions"])
    assert any(a["solution"].endswith("…") for a in package["actions"])


def test_json_export_stays_complete(ws, monkeypatch, tmp_path):
    monkeypatch.setattr(service, "MAX_REFERENCES", 3)
    monkeypatch.setattr(service, "MAX_SOLUTION_CHARS", 12)
    result = ws.export(OPENSSH, write=True, confirm=True)
    name = next(n for n in result["written"] if n.endswith(".json"))
    path = tmp_path / "e" / name
    package = json.loads(path.read_text(encoding="utf-8"))["package"]
    assert len(package["cves"]) == 29 and len(package["advisories"]) == 14
