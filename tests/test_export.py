import csv
import dataclasses
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest
from test_cluster import finding

from exposure_case.case import build_case_file, build_package_view
from exposure_case.cluster import build_clusters
from exposure_case.export import (
    ExportError,
    case_json,
    case_markdown,
    csv_cell,
    md_cell,
    md_text,
    package_actions_csv,
    package_hosts_csv,
    package_json,
    package_markdown,
    write_case_export,
    write_package_export,
)
from exposure_case.fixes import build_fix_packages, rank_packages
from exposure_case.links import link_cases_and_fixes
from exposure_case.scoring import fleet_size, rank_clusters

NOW = datetime(2026, 11, 2, tzinfo=timezone.utc)
GOLDEN = Path(__file__).parent / "golden"


def fx(fid, plugin=1, asset="a1", severity="high", cpe="cpe:/a:v:p", solution="Update the package.", **extra):
    return finding(fid, plugin=plugin, asset=asset, severity=severity, solution=solution, cpe=[cpe], **extra)


def build(recs):
    cases, packages = build_clusters(recs), build_fix_packages(recs)
    links = link_cases_and_fixes(cases, packages)
    fleet = fleet_size(recs)
    return rank_clusters(cases, fleet, NOW), rank_packages(packages, fleet, NOW), links


@pytest.fixture
def world():
    recs = [
        fx("f1", plugin=1, asset="a1", severity="critical", exploit_available=True, cve=["CVE-2023-1"],
           see_also=["https://example.test/adv1"], solution="Upgrade to widget 2.0 or later."),
        fx("f2", plugin=1, asset="a2", severity="critical", exploit_available=True, cve=["CVE-2023-1"],
           see_also=["https://example.test/adv1"], solution="Upgrade to widget 2.0 or later."),
        fx("f3", plugin=2, asset="a1", severity="medium", exploit_available=False, solution="Upgrade to widget 2.1.",
           vpr={"on_cisa_kev": True}),
    ]
    cases, packages, links = build(recs)
    return recs, cases, packages, links


def package_view(world, pid="fix:v-p:patch"):
    _, _, packages, links = world
    return build_package_view(next(r for r in packages if r.package.package_id == pid), links, NOW)


def case_file(world, cid="plugin:1"):
    _, cases, _, links = world
    return build_case_file(next(r for r in cases if r.cluster.cluster_id == cid), links, NOW)


# --- sanitizers ---

def test_md_text_neutralizes_html_and_control_characters():
    out = md_text("<script>alert(1)</script>\x00\x1b[31m hi\nthere")
    assert not re.search(r"(?<!\\)[<>]", out)  # every angle bracket is backslash-escaped
    assert "\x00" not in out and "\x1b" not in out and "\n" not in out
    assert md_text("OpenSSH < 10.4") == "OpenSSH \\< 10.4"


def test_md_cell_escapes_pipes_and_backticks():
    out = md_cell("a | b `c`")
    assert "|" not in out.replace("\\|", "") and "`" not in out


@pytest.mark.parametrize("bad", ["=cmd|' /C calc'!A0", "+1+1", "-2+3", "@SUM(A1)", "\t=1", "\r=1"])
def test_csv_cell_neutralizes_formulas(bad):
    assert csv_cell(bad).startswith("'")


def test_csv_cell_leaves_normal_values_alone():
    assert csv_cell("HOST-1") == "HOST-1" and csv_cell(5) == 5 and csv_cell(0.25) == 0.25 and csv_cell("") == ""


# --- engineer handoff ---

SECTIONS = ["# Fix:", "## What to do", "## Impact", "## Affected hosts", "## References", "## Cases this relieves",
            "## Source records"]


def test_package_markdown_has_all_sections_in_order(world):
    md = package_markdown(package_view(world))
    positions = [md.index(s) for s in SECTIONS]
    assert positions == sorted(positions)


def test_package_markdown_labels_tenable_text_and_scope(world):
    md = package_markdown(package_view(world))
    assert "Tenable-provided" in md and "does not state that one update supersedes another" in md
    assert "Upgrade to widget 2.0 or later." in md and "CVE-2023-1" in md and "https://example.test/adv1" in md
    assert "contained in this package" in md.lower()


def test_package_markdown_shows_priority_and_relieved_cases(world):
    md = package_markdown(package_view(world))
    assert "priority #" in md and "plugin:1" in md and "Why it ranks here" in md


def test_package_markdown_caps_hosts_but_csv_has_all(world):
    recs = [fx(f"f{i}", asset=f"a{i:03d}") for i in range(40)]
    _, packages, links = build(recs)
    view = build_package_view(packages[0], links, NOW)
    md = package_markdown(view, max_hosts=25)
    assert "Showing 25 of 40 hosts" in md and "full list is in the CSV" in md
    rows = list(csv.reader(io.StringIO(package_hosts_csv(view))))
    assert len(rows) == 41  # header + all 40 hosts


def test_package_markdown_caps_actions(world):
    recs = [fx(f"f{i}", plugin=i, solution=f"Upgrade to widget {i}.") for i in range(1, 30)]
    _, packages, links = build(recs)
    md = package_markdown(build_package_view(packages[0], links, NOW), max_actions=10)
    assert "plus 19 more actions" in md
    rows = list(csv.reader(io.StringIO(package_actions_csv(build_package_view(packages[0], links, NOW)))))
    assert len(rows) == 30


def test_hostile_tenable_text_is_neutralized_everywhere(world):
    evil = dataclasses.replace(fx("f9", plugin=9, asset="a9", solution="Upgrade <img src=x onerror=alert(1)> now"),
                               hostname="=HYPERLINK(\"http://evil\")|<b>x</b>")
    _, packages, links = build([evil])
    view = build_package_view(packages[0], links, NOW)
    md = package_markdown(view)
    assert not re.search(r"(?<!\\)<", md) and "=HYPERLINK" in md  # text kept, markup defused
    host_row = list(csv.reader(io.StringIO(package_hosts_csv(view))))[1]
    assert any(cell.startswith("'=HYPERLINK") for cell in host_row)
    action_row = list(csv.reader(io.StringIO(package_actions_csv(view))))[1]
    assert not any(cell.startswith(("=", "+", "-", "@")) for cell in action_row)


def test_hosts_csv_header_and_values(world):
    rows = list(csv.reader(io.StringIO(package_hosts_csv(package_view(world)))))
    assert rows[0] == ["asset_uuid", "hostname", "ipv4", "operating_system", "findings", "plugins",
                       "worst_severity", "oldest_first_found"]
    assert {r[0] for r in rows[1:]} == {"a1", "a2"}


def test_actions_csv_has_per_action_critical_share(world):
    rows = list(csv.DictReader(io.StringIO(package_actions_csv(package_view(world)))))
    assert rows[0]["solution"] == "Upgrade to widget 2.0 or later." and float(rows[0]["critical_share"]) == 1.0
    assert rows[0]["critical_findings"] == "2"


def test_package_json_round_trips_and_is_deterministic(world):
    view = package_view(world)
    data = json.loads(package_json(view))
    assert data["package"]["package_id"] == "fix:v-p:patch" and data["evidence_ids"] == ["f1", "f2", "f3"]
    assert package_json(view) == package_json(package_view(world))
    assert data["package"]["hosts_total"] == len(data["package"]["hosts"])  # JSON is never truncated


# --- analyst case file ---

CASE_SECTIONS = ["# Case:", "## Summary", "## Score breakdown", "## Fix packages that address this case",
                 "## Top vulnerabilities", "## Affected hosts", "## Timeline", "## Limitations",
                 "## Source records", "## Disposition"]


def test_case_markdown_sections_and_disposition_slot(world):
    md = case_markdown(case_file(world))
    positions = [md.index(s) for s in CASE_SECTIONS]
    assert positions == sorted(positions)
    assert "Not yet recorded" in md and "fix:v-p:patch" in md and "CVE-2023-1" in md


def test_case_markdown_shows_score_breakdown_and_no_verdict_language(world):
    md = case_markdown(case_file(world)).lower()
    assert "| severity |" in md and "points" in md
    assert not any(word in md for word in ("disciplin", "terminate", "should be fired", "guilty"))


def test_case_json_round_trips(world):
    cf = case_file(world)
    data = json.loads(case_json(cf))
    assert data["case_id"] == "plugin:1" and data["disposition"] is None and data["evidence_ids"] == ["f1", "f2"]


# --- writing files ---

def test_write_requires_confirm(world, tmp_path):
    with pytest.raises(ExportError, match="confirm"):
        write_package_export(package_view(world), tmp_path, confirm=False)
    assert list(tmp_path.iterdir()) == []


def test_write_package_export_creates_three_files_with_safe_names(world, tmp_path):
    paths = write_package_export(package_view(world), tmp_path / "exports", confirm=True)
    names = {p.name for p in paths}
    stem = next(iter(names)).split(".")[0].replace("-hosts", "").replace("-actions", "")
    assert re.fullmatch(r"fix-v-p-patch-[0-9a-f]{8}", stem)
    assert names == {f"{stem}.md", f"{stem}.json", f"{stem}-hosts.csv", f"{stem}-actions.csv"}
    assert all(p.parent == (tmp_path / "exports") for p in paths)
    assert all(p.read_text(encoding="utf-8") for p in paths)


def test_write_case_export_files(world, tmp_path):
    paths = write_case_export(case_file(world), tmp_path, confirm=True)
    assert {p.suffix for p in paths} == {".md", ".json", ".csv"}
    assert all(p.parent == tmp_path for p in paths)


def test_write_never_escapes_the_output_directory(world, tmp_path):
    view = package_view(world)
    hostile = dataclasses.replace(view, package=dataclasses.replace(view.package, package_id="../../etc/passwd"))
    paths = write_package_export(hostile, tmp_path / "out", confirm=True)
    assert all((tmp_path / "out") in p.parents for p in paths)
    assert not (tmp_path / "etc").exists()


def test_write_is_idempotent(world, tmp_path):
    first = {p.name: p.read_bytes() for p in write_package_export(package_view(world), tmp_path, confirm=True)}
    second = {p.name: p.read_bytes() for p in write_package_export(package_view(world), tmp_path, confirm=True)}
    assert first == second


# --- golden file ---

def test_package_markdown_matches_golden(world):
    golden = GOLDEN / "package_basic.md"
    assert golden.read_text(encoding="utf-8") == package_markdown(package_view(world))


def test_case_markdown_matches_golden(world):
    golden = GOLDEN / "case_basic.md"
    assert golden.read_text(encoding="utf-8") == case_markdown(case_file(world))


# --- readability caps (from reading real output) ---

def test_cases_relieved_list_is_capped(world):
    recs = [fx(f"f{i}", plugin=i, asset=f"a{i}") for i in range(1, 31)]
    _, packages, links = build(recs)
    md = package_markdown(build_package_view(packages[0], links, NOW), max_cases=10)
    assert md.count("- `plugin:") == 10 and "plus 20 more cases in the JSON" in md


def test_zero_critical_share_shows_a_dash(world):
    recs = [fx("f1", severity="high", solution="Upgrade to widget 2.0.")]
    _, packages, links = build(recs)
    md = package_markdown(build_package_view(packages[0], links, NOW))
    assert "| high | \u2013 |" in md


def test_nonzero_critical_share_shows_a_percentage(world):
    md = package_markdown(package_view(world))
    assert "| critical | 100.0% |" in md
