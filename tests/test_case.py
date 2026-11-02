import dataclasses
from datetime import datetime, timezone

import pytest
from test_cluster import finding

from exposure_case.case import build_case_file, build_package_view
from exposure_case.cluster import build_clusters
from exposure_case.fixes import build_fix_packages, rank_packages
from exposure_case.links import link_cases_and_fixes
from exposure_case.scoring import fleet_size, rank_clusters

NOW = datetime(2026, 11, 2, tzinfo=timezone.utc)


def fx(fid, plugin=1, asset="a1", severity="high", cpe="cpe:/a:v:p", solution="Update the package.", **extra):
    return finding(fid, plugin=plugin, asset=asset, severity=severity, solution=solution, cpe=[cpe], **extra)


@pytest.fixture
def world():
    recs = [
        fx("f1", plugin=1, asset="a1", severity="critical", exploit_available=True, cve=["CVE-1"]),
        fx("f2", plugin=1, asset="a2", severity="critical", exploit_available=True, cve=["CVE-1"]),
        fx("f3", plugin=2, asset="a1", severity="low", solution="Disable the service.", exploit_available=False),
        fx("f4", plugin=3, asset="a3", severity="medium", cpe="cpe:/a:o:o", exploit_available=False,
           vpr={"on_cisa_kev": True}, state="REOPENED"),
    ]
    cases, packages = build_clusters(recs), build_fix_packages(recs)
    links = link_cases_and_fixes(cases, packages)
    fleet = fleet_size(recs)
    return recs, rank_clusters(cases, fleet, NOW), rank_packages(packages, fleet, NOW), links


def case_by_id(ranked, cid):
    return next(r for r in ranked if r.cluster.cluster_id == cid)


def test_case_file_carries_identity_rank_and_score(world):
    _, cases, _, links = world
    cf = build_case_file(case_by_id(cases, "plugin:1"), links, NOW)
    assert cf.case_id == "plugin:1" and cf.kind == "plugin" and cf.rank == case_by_id(cases, "plugin:1").rank
    assert cf.score.total == case_by_id(cases, "plugin:1").score.total
    assert cf.disposition is None


def test_facts_are_computed_from_the_findings(world):
    _, cases, _, links = world
    f = build_case_file(case_by_id(cases, "plugin:1"), links, NOW).facts
    assert (f["hosts"], f["findings"], f["vulnerabilities"]) == (2, 2, 1)
    assert f["by_severity"] == {"critical": 2} and f["exploitable_findings"] == 2 and f["kev_findings"] == 0


def test_kev_and_reopened_counted(world):
    _, cases, _, links = world
    f = build_case_file(case_by_id(cases, "plugin:3"), links, NOW).facts
    assert f["kev_findings"] == 1 and f["reopened_findings"] == 1


def test_case_lists_the_fix_packages_that_clear_it(world):
    _, cases, _, links = world
    cf = build_case_file(case_by_id(cases, "plugin:1"), links, NOW)
    assert [(f.other_id, f.findings, f.share) for f in cf.fixes] == [("fix:v-p:patch", 2, 1.0)]


def test_vulnerabilities_sorted_worst_first_with_references(world):
    _, cases, _, links = world
    cf = build_case_file(case_by_id(cases, "plugin:1"), links, NOW)
    v = cf.vulnerabilities[0]
    assert (v.plugin_id, v.severity, v.hosts, v.cves) == (1, "critical", 2, ("CVE-1",))
    assert v.solution == "Update the package."


def test_hosts_and_timeline_present(world):
    _, cases, _, links = world
    cf = build_case_file(case_by_id(cases, "plugin:1"), links, NOW)
    assert [h.asset_uuid for h in cf.hosts] == ["a1", "a2"] and len(cf.timeline) >= 1


def test_evidence_ids_cover_every_active_finding(world):
    _, cases, _, links = world
    cf = build_case_file(case_by_id(cases, "plugin:1"), links, NOW)
    assert cf.evidence_ids == ("f1", "f2")


def test_limitations_are_stated(world):
    _, cases, _, links = world
    text = " ".join(build_case_file(case_by_id(cases, "plugin:1"), links, NOW).limitations)
    assert "masked" in text and "not a verdict" in text.lower()


def test_case_file_json_ready_and_deterministic(world):
    _, cases, _, links = world
    a = build_case_file(case_by_id(cases, "plugin:1"), links, NOW).to_dict()
    b = build_case_file(case_by_id(cases, "plugin:1"), links, NOW).to_dict()
    assert a == b and a["disposition"] is None
    assert {"case_id", "score", "facts", "fixes", "hosts", "vulnerabilities", "timeline", "limitations",
            "evidence_ids", "facts_summary"} <= set(a)


def test_facts_summary_lines_are_plain_statements(world):
    _, cases, _, links = world
    lines = build_case_file(case_by_id(cases, "plugin:1"), links, NOW).facts_summary
    assert any("2 hosts" in line for line in lines) and all(line.endswith(".") for line in lines)


# --- package view ---

def test_package_view_has_priority_and_cases_relieved(world):
    _, _, packages, links = world
    ranked = next(r for r in packages if r.package.package_id == "fix:v-p:patch")
    view = build_package_view(ranked, links, NOW)
    assert view.rank == ranked.rank and view.package is ranked.package
    assert [c.other_id for c in view.cases] == ["plugin:1"]
    assert view.priority_reasons and all(isinstance(r, str) for r in view.priority_reasons)


def test_package_view_dict_matches_package_and_notes_scope(world):
    _, _, packages, links = world
    ranked = next(r for r in packages if r.package.package_id == "fix:v-p:patch")
    d = build_package_view(ranked, links, NOW).to_dict()
    assert d["package"]["package_id"] == "fix:v-p:patch" and d["rank"] == ranked.rank
    assert "does not state" in d["scope_note"]
    assert d["evidence_ids"] == ["f1", "f2"]


def test_case_file_is_frozen(world):
    _, cases, _, links = world
    cf = build_case_file(case_by_id(cases, "plugin:1"), links, NOW)
    with pytest.raises(dataclasses.FrozenInstanceError):
        cf.title = "x"  # type: ignore[misc]
