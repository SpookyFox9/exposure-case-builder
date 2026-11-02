from datetime import datetime, timezone

import pytest
from test_cluster import finding

from exposure_case.cluster import build_clusters
from exposure_case.fixes import as_cluster, build_fix_packages, rank_packages
from exposure_case.links import link_cases_and_fixes

NOW = datetime(2026, 11, 2, tzinfo=timezone.utc)
RH = "Red Hat Local Security Checks"


def fx(fid, plugin, cpe, asset="a1", family="General", severity="high", **extra):
    return finding(fid, plugin=plugin, asset=asset, family=family, severity=severity,
                   solution="Update the package.", cpe=[cpe], **extra)


@pytest.fixture
def world():
    """One patch-family case spanning two products; one product spanning the family case and a plugin case."""
    recs = [
        fx("f1", 1, "cpe:/o:redhat:enterprise_linux", family=RH),
        fx("f2", 2, "cpe:/o:redhat:enterprise_linux", family=RH, asset="a2"),
        fx("f3", 3, "cpe:/a:gnu:bash", family=RH),
        fx("f4", 4, "cpe:/a:gnu:bash", family="General", asset="a2"),
    ]
    return recs, build_clusters(recs), build_fix_packages(recs)


def test_case_to_fix_links_cover_every_finding(world):
    _, cases, packages = world
    links = link_cases_and_fixes(cases, packages)
    for case in cases:
        assert sum(link.findings for link in links.fixes_for(case.cluster_id)) == len(case.active)
        assert sum(link.share for link in links.fixes_for(case.cluster_id)) == pytest.approx(1.0)


def test_fix_to_case_links_cover_every_finding(world):
    _, cases, packages = world
    links = link_cases_and_fixes(cases, packages)
    for package in packages:
        assert sum(link.findings for link in links.cases_for(package.package_id)) == len(package.active)
        assert sum(link.share for link in links.cases_for(package.package_id)) == pytest.approx(1.0)


def test_many_to_many_shape(world):
    _, cases, packages = world
    links = link_cases_and_fixes(cases, packages)
    family_case = links.fixes_for("family:red-hat-local-security-checks")
    assert {(link.other_id, link.findings) for link in family_case} == {
        ("fix:redhat-enterprise-linux:patch", 2), ("fix:gnu-bash:patch", 1)}
    bash = links.cases_for("fix:gnu-bash:patch")
    assert {(link.other_id, link.findings) for link in bash} == {("family:red-hat-local-security-checks", 1), ("plugin:4", 1)}


def test_links_are_sorted_largest_first_then_id(world):
    _, cases, packages = world
    links = link_cases_and_fixes(cases, packages)
    first = links.fixes_for("family:red-hat-local-security-checks")
    assert [link.other_id for link in first] == ["fix:redhat-enterprise-linux:patch", "fix:gnu-bash:patch"]


def test_links_carry_titles_for_display(world):
    _, cases, packages = world
    link = link_cases_and_fixes(cases, packages).fixes_for("plugin:4")[0]
    assert link.title == "gnu:bash (patch)"


def test_unknown_ids_return_empty(world):
    _, cases, packages = world
    links = link_cases_and_fixes(cases, packages)
    assert links.fixes_for("nope") == () and links.cases_for("nope") == ()


def test_inconsistent_universes_are_rejected(world):
    recs, cases, _ = world
    with pytest.raises(ValueError, match="not in"):
        link_cases_and_fixes(cases, build_fix_packages(recs[:3]))


# --- ranking packages with the same approved weights ---

def test_as_cluster_exposes_the_package_findings(world):
    _, _, packages = world
    c = as_cluster(packages[0])
    assert c.active == packages[0].active and c.plugin_ids == packages[0].plugin_ids and c.kind == "fix"


def test_rank_packages_orders_by_score_then_id():
    recs = [fx("f1", 1, "cpe:/a:v:low", severity="low", exploit_available=False),
            fx("f2", 2, "cpe:/a:v:crit", severity="critical", exploited_by_malware=True),
            fx("f3", 3, "cpe:/a:v:med", severity="medium", exploit_available=False)]
    ranked = rank_packages(build_fix_packages(recs), 10, NOW)
    assert [r.package.product for r in ranked] == ["v:crit", "v:med", "v:low"]
    assert [r.rank for r in ranked] == [1, 2, 3]
    assert ranked[0].score.total > ranked[1].score.total


def test_rank_is_independent_of_input_order():
    recs = [fx(f"f{i}", i, f"cpe:/a:v:p{i}", severity="medium") for i in range(1, 6)]
    a = [r.package.package_id for r in rank_packages(build_fix_packages(recs), 10, NOW)]
    b = [r.package.package_id for r in rank_packages(build_fix_packages(list(reversed(recs))), 10, NOW)]
    assert a == b
