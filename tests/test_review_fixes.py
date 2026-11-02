"""Regressions from the code review of the fix view (commit 7dfb170)."""

import dataclasses
import random
from datetime import datetime, timezone

import pytest
from test_cluster import finding
from test_ingest import raw_record

from exposure_case.cluster import build_clusters
from exposure_case.fixes import build_fix_packages, classify_fix, normalize_product
from exposure_case.ingest import MAX_LIST_ITEMS, MAX_TEXT_CHARS, parse_record
from exposure_case.links import link_cases_and_fixes
from exposure_case.scoring import score_cluster

NOW = datetime(2026, 11, 2, tzinfo=timezone.utc)


def fx(fid, plugin=1, asset="a1", cpe="cpe:/a:v:p", solution="Update the package.", severity="high", **extra):
    return finding(
        fid, plugin=plugin, asset=asset, severity=severity, solution=solution, cpe=[cpe] if cpe else [], **extra
    )


# --- ingest: overflow, size caps ---


@pytest.mark.parametrize("field", ["cvss3_base_score", "epss_score"])
@pytest.mark.parametrize("bad", [10**400, -(10**400), float("nan"), float("inf")])
def test_huge_or_non_finite_numbers_do_not_abort_ingest(field, bad):
    raw = raw_record()
    raw["plugin"][field] = bad
    r = parse_record(raw)
    assert getattr(r, field) is None


def test_huge_numbers_in_vpr_and_fix_seconds_do_not_abort_ingest():
    raw = raw_record(time_taken_to_fix=10**400)
    raw["plugin"]["vpr"] = {"score": 10**400}
    r = parse_record(raw)
    assert r.vpr_score is None


def test_long_lists_and_strings_are_capped():
    raw = raw_record(output="x" * (MAX_TEXT_CHARS * 10))
    raw["plugin"].update(
        see_also=[f"https://e.test/{i}" for i in range(MAX_LIST_ITEMS * 10)],
        cve=[f"CVE-{i}" for i in range(MAX_LIST_ITEMS * 10)],
        solution="s" * (MAX_TEXT_CHARS * 10),
    )
    r = parse_record(raw)
    assert len(r.see_also) == len(r.cves) == MAX_LIST_ITEMS
    assert len(r.solution) <= MAX_TEXT_CHARS + 20 and r.solution.endswith("[truncated]")
    assert len(r.output) <= MAX_TEXT_CHARS * 2 + 20


# --- classify_fix ---


@pytest.mark.parametrize(
    "solution,expected",
    [
        ("Patch the affected systems.", "patch"),
        ("Updates are available from the vendor.", "patch"),
        ("Please apply the vendor patch.", "patch"),
        ("Note: install the latest release.", "patch"),
        ("Apply the workaround and disable the service.", "configuration"),
        ("Microsoft recommends disabling the service.", "configuration"),
        ("Microsoft has released KB5039217 to address this issue.", "patch"),
    ],
)
def test_classify_fix_edge_cases(solution, expected):
    assert classify_fix(solution) == expected


# --- normalize_product ---


@pytest.mark.parametrize(
    "cpe,expected",
    [
        (r"cpe:2.3:a:v:pro\:duct:1.0:*:*:*:*:*:*:*", "v:pro_duct"),
        ("cpe:2.3:a:-:foo:*:*:*:*:*:*:*:*", ""),
        ("cpe:/a:v:-", ""),
        ("cpe:/a:v:p?", ""),
        ("cpe:2.3:a:v:*:*:*:*:*:*:*:*:*", ""),
    ],
)
def test_normalize_product_edge_cases(cpe, expected):
    assert normalize_product(cpe) == expected


# --- package ids ---


def test_colliding_slugs_get_distinct_deterministic_ids():
    recs = [fx("f1", plugin=1, cpe="cpe:/a:a_b:c"), fx("f2", plugin=2, cpe="cpe:/a:a:b_c")]
    ids = [p.package_id for p in build_fix_packages(recs)]
    assert len(ids) == len(set(ids)) == 2
    assert ids == [p.package_id for p in build_fix_packages(list(reversed(recs)))]
    assert {p.product for p in build_fix_packages(recs)} == {"a_b:c", "a:b_c"}


def test_non_colliding_ids_stay_readable():
    assert [p.package_id for p in build_fix_packages([fx("f1")])] == ["fix:v-p:patch"]


def test_packages_identical_for_shuffled_input():
    recs = [fx(f"f{i}", plugin=i, asset=f"a{i % 4}", cpe=f"cpe:/a:v{i % 5}:p", severity="medium") for i in range(1, 40)]
    base = [p.to_dict() for p in build_fix_packages(recs)]
    for seed in range(5):
        shuffled = recs[:]
        random.Random(seed).shuffle(shuffled)
        assert [p.to_dict() for p in build_fix_packages(shuffled)] == base


# --- impact must not imply one fix clears everything ---


def test_impact_states_how_many_distinct_actions_it_spans():
    recs = [
        fx("f1", plugin=1, solution="Apply Security Update 111"),
        fx("f2", plugin=2, solution="Apply Security Update 222"),
    ]
    pkg = build_fix_packages(recs)[0]
    assert pkg.impact.actions == 2 == len(pkg.actions)
    assert pkg.to_dict()["impact"]["actions"] == 2


def test_each_action_carries_its_own_critical_share():
    recs = [
        fx("f1", plugin=1, solution="Apply Security Update 111", severity="critical"),
        fx("f2", plugin=2, solution="Apply Security Update 222", severity="critical", asset="a2"),
        fx("f3", plugin=3, cpe="cpe:/a:o:o", severity="critical", asset="a3"),
        fx("f4", plugin=4, cpe="cpe:/a:o:o", severity="critical", asset="a4"),
    ]
    pkg = {p.product: p for p in build_fix_packages(recs)}["v:p"]
    assert [a.critical_findings for a in pkg.actions] == [1, 1]
    assert [round(a.critical_share, 3) for a in pkg.actions] == [0.25, 0.25]
    assert pkg.impact.critical_share == pytest.approx(0.5)
    assert sum(a.critical_share for a in pkg.actions) == pytest.approx(pkg.impact.critical_share)


# --- host table uses the latest details ---


def test_host_table_shows_latest_name_and_oldest_first_seen():
    old = dataclasses.replace(
        fx("f1"),
        hostname="OLD",
        first_found=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_found=datetime(2026, 2, 1, tzinfo=timezone.utc),
    )
    new = dataclasses.replace(
        fx("f2", plugin=2),
        hostname="NEW",
        first_found=datetime(2026, 5, 1, tzinfo=timezone.utc),
        last_found=datetime(2026, 11, 1, tzinfo=timezone.utc),
    )
    host = build_fix_packages([old, new])[0].hosts[0]
    assert host.hostname == "NEW" and host.oldest_first_found == old.first_found


# --- exploit reason is order independent ---


def test_exploit_reason_does_not_depend_on_record_order():
    a = fx("f1", plugin=1, exploit_available=False, vpr={"score": 9.1})
    b = fx("f2", plugin=2, asset="a2", exploit_available=False, vpr={"score": 9.8})
    k = fx("f3", plugin=3, asset="a3", exploit_available=False, vpr={"on_cisa_kev": True})
    m = fx("f4", plugin=4, asset="a4", exploit_available=False, exploited_by_malware=True)
    details = set()
    for order in ([a, b, k, m], [m, k, b, a], [b, m, a, k]):
        case = build_clusters(order)
        # merge into one cluster by reusing a single cluster built from a patch family
        details.add(
            tuple(
                sorted(c.detail for cl in case for c in score_cluster(cl, 100, NOW).components if c.name == "exploit")
            )
        )
    assert len(details) == 1


def test_exploit_reason_tie_is_resolved_by_text_not_position():
    family = "Red Hat Local Security Checks"
    a = fx("f1", plugin=1, exploit_available=False, vpr={"score": 9.1})
    b = fx("f2", plugin=2, exploit_available=False, vpr={"score": 9.8})
    for r in (a, b):
        pass
    a, b = (dataclasses.replace(r, plugin_family=family) for r in (a, b))
    d1 = [c.detail for c in score_cluster(build_clusters([a, b])[0], 100, NOW).components if c.name == "exploit"]
    d2 = [c.detail for c in score_cluster(build_clusters([b, a])[0], 100, NOW).components if c.name == "exploit"]
    assert d1 == d2


# --- links: a finding in two cases is rejected ---


def test_links_reject_a_finding_present_in_two_cases():
    recs = [fx("f1", plugin=1), fx("f2", plugin=2, asset="a2")]
    cases, packages = build_clusters(recs), build_fix_packages(recs)
    dup = dataclasses.replace(cases[1], active=cases[1].active + cases[0].active)
    with pytest.raises(ValueError, match="more than once"):
        link_cases_and_fixes((cases[0], dup), packages)
