import dataclasses
from datetime import datetime, timezone

import pytest
from test_cluster import finding

from exposure_case.fixes import (
    FixPackage,
    build_fix_packages,
    classify_fix,
    normalize_product,
)

SSH = "cpe:/a:openbsd:openssh"


def fx(fid, asset="a1", plugin=1, solution="Upgrade to OpenSSH 9.6 or later.", cpe=SSH, severity="high", **extra):
    return finding(fid, plugin=plugin, asset=asset, severity=severity, solution=solution,
                   cpe=[cpe] if cpe else [], **extra)


def by_id(packages):
    return {p.package_id: p for p in packages}


# --- helpers ---

@pytest.mark.parametrize(
    "cpe,expected",
    [
        ("cpe:/a:openbsd:openssh", "openbsd:openssh"),
        ("cpe:/o:centos:centos", "centos:centos"),
        ("cpe:/a:centos:centos", "centos:centos"),  # /a: and /o: aliases merge
        ("cpe:/a:Apache:Log4j:1.2", "apache:log4j"),
        ("cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:*", "oracle:jdk"),
        ("cpe:/o:microsoft:windows_10_1809", "microsoft:windows_10_1809"),
        ("", ""),
        ("garbage", ""),
        ("cpe:/a:onlyvendor", ""),
    ],
)
def test_normalize_product(cpe, expected):
    assert normalize_product(cpe) == expected


@pytest.mark.parametrize(
    "solution,expected",
    [
        ("Update the affected packages.", "patch"),
        ("Upgrade to OpenSSH 9.6 or later.", "patch"),
        ("Apply Security Update 5039217", "patch"),
        ("Install the vendor patch.", "patch"),
        ("Microsoft has released KB4493478 to address this issue.", "patch"),
        ("Disable J-Web, or limit access to only trusted hosts.", "configuration"),
        ("Contact the vendor or consult product documentation to disable CBC mode.", "configuration"),
        ("Filter out the ICMP timestamp requests (13).", "configuration"),
        ("  upgrade   now ", "patch"),
        ("Contact the vendor for an update with the strict key exchange countermeasures.", "patch"),
        ("Contact the vendor for a patch.", "patch"),
        ("Contact the vendor to update and disable CBC mode ciphers.", "configuration"),
        ("Contact the vendor or consult product documentation to remove the weak algorithms.", "configuration"),
        ("", "unspecified"),
        ("   ", "unspecified"),
    ],
)
def test_classify_fix(solution, expected):
    assert classify_fix(solution) == expected


# --- grouping ---

def test_same_product_and_fix_type_share_one_package():
    ps = build_fix_packages([fx("f1", plugin=1), fx("f2", plugin=2, asset="a2"), fx("f3", plugin=3, cpe="cpe:/a:v:other")])
    ids = by_id(ps)
    assert set(ids) == {"fix:openbsd-openssh:patch", "fix:v-other:patch"}
    ssh = ids["fix:openbsd-openssh:patch"]
    assert ssh.product == "openbsd:openssh" and ssh.fix_type == "patch"
    assert ssh.plugin_ids == (1, 2) and ssh.impact.hosts == 2


def test_patch_and_configuration_fixes_for_one_product_stay_separate():
    ps = by_id(build_fix_packages([
        fx("f1", plugin=1),
        fx("f2", plugin=2, solution="Contact the vendor to disable CBC mode ciphers."),
    ]))
    assert set(ps) == {"fix:openbsd-openssh:patch", "fix:openbsd-openssh:configuration"}


def test_no_cpe_falls_back_to_the_plugin():
    ps = build_fix_packages([fx("f1", plugin=77, cpe="")])
    assert [p.package_id for p in ps] == ["fix:plugin-77:patch"] and ps[0].product == ""


def test_cpe_aliases_merge_into_one_package():
    ps = build_fix_packages([fx("f1", plugin=1, cpe="cpe:/a:centos:centos"), fx("f2", plugin=2, cpe="cpe:/o:centos:centos")])
    assert [p.package_id for p in ps] == ["fix:centos-centos:patch"]


def test_info_and_fixed_findings_are_excluded_but_fixed_is_counted():
    ps = build_fix_packages([fx("f1"), fx("f2", severity="info", plugin=2), fx("f3", state="FIXED", plugin=3)])
    assert len(ps) == 1 and ps[0].impact.findings == 1 and ps[0].fixed_findings == 1


def test_package_with_only_fixed_findings_is_dropped():
    assert build_fix_packages([fx("f1", state="FIXED")]) == ()


def test_every_active_finding_lands_in_exactly_one_package():
    recs = [fx(f"f{i}", plugin=i, asset=f"a{i % 3}", cpe=f"cpe:/a:v{i % 4}:p") for i in range(1, 25)]
    ps = build_fix_packages(recs)
    ids = [e.record_id for p in ps for e in p.evidence()]
    assert sorted(ids) == sorted(r.finding_id for r in recs) and len(ids) == len(set(ids))


def test_packages_are_sorted_and_deterministic():
    recs = [fx("f1", plugin=1, cpe="cpe:/a:z:z"), fx("f2", plugin=2, cpe="cpe:/a:a:a"), fx("f3", plugin=3, cpe="cpe:/a:m:m")]
    a = [p.package_id for p in build_fix_packages(recs)]
    assert a == sorted(a) == [p.package_id for p in build_fix_packages(list(reversed(recs)))]


# --- contents ---

def test_actions_list_distinct_solutions_with_counts_largest_first():
    ps = build_fix_packages([
        fx("f1", plugin=1, solution="Upgrade to OpenSSH 9.6."),
        fx("f2", plugin=2, asset="a2", solution="Upgrade to OpenSSH 9.6."),
        fx("f3", plugin=3, solution="Upgrade to OpenSSH 9.8."),
    ])
    acts = ps[0].actions
    assert [(a.solution, a.plugins, a.findings, a.hosts) for a in acts] == [
        ("Upgrade to OpenSSH 9.6.", 2, 2, 2), ("Upgrade to OpenSSH 9.8.", 1, 1, 1)]


def test_host_table_summarises_each_host():
    ps = build_fix_packages([
        fx("f1", plugin=1, asset="a1", severity="low"),
        fx("f2", plugin=2, asset="a1", severity="critical"),
        fx("f3", plugin=3, asset="a2", severity="medium"),
    ])
    hosts = {h.asset_uuid: h for h in ps[0].hosts}
    assert (hosts["a1"].findings, hosts["a1"].plugins, hosts["a1"].worst_severity) == (2, 2, "critical")
    assert hosts["a2"].worst_severity == "medium"
    assert [h.asset_uuid for h in ps[0].hosts] == ["a1", "a2"]  # worst severity first, then id


def test_impact_counts_and_fleet_share():
    recs = [fx("f1", plugin=1, asset="a1", severity="critical"), fx("f2", plugin=2, asset="a2", severity="critical"),
            fx("f3", plugin=3, asset="a3", severity="high", cpe="cpe:/a:o:o"),
            fx("f4", plugin=4, asset="a4", severity="critical", cpe="cpe:/a:o:o")]
    pk = by_id(build_fix_packages(recs))
    ssh = pk["fix:openbsd-openssh:patch"].impact
    assert (ssh.plugins, ssh.findings, ssh.hosts) == (2, 2, 2)
    assert ssh.by_severity == {"critical": 2}
    assert ssh.critical_share == pytest.approx(2 / 3)  # 2 of the fleet's 3 critical findings


def test_impact_exploitability_signals():
    # the shared record helper defaults exploit_available to True, so set it explicitly
    recs = [fx("f1", plugin=1, exploit_available=True),
            fx("f2", plugin=2, exploit_available=False, exploited_by_malware=True),
            fx("f3", plugin=3, exploit_available=False, vpr={"on_cisa_kev": True}),
            fx("f4", plugin=4, exploit_available=False)]
    imp = build_fix_packages(recs)[0].impact
    assert (imp.exploitable_findings, imp.malware_findings, imp.kev_findings) == (1, 1, 1)


def test_references_are_unique_and_sorted():
    ps = build_fix_packages([
        fx("f1", plugin=1, cve=["CVE-2", "CVE-1"], see_also=["https://b.test", "https://a.test"]),
        fx("f2", plugin=2, asset="a2", cve=["CVE-1"], see_also=["https://a.test"]),
    ])
    assert ps[0].cves == ("CVE-1", "CVE-2") and ps[0].advisories == ("https://a.test", "https://b.test")


def test_evidence_points_at_every_active_finding():
    ps = build_fix_packages([fx("fb"), fx("fa", plugin=2, asset="a2")])
    assert [e.record_id for e in ps[0].evidence()] == ["fa", "fb"]


def test_package_is_frozen_and_serialises():
    p = build_fix_packages([fx("f1")])[0]
    assert isinstance(p, FixPackage)
    with pytest.raises(dataclasses.FrozenInstanceError):
        p.title = "x"  # type: ignore[misc]
    d = p.to_dict(max_hosts=1)
    assert d["package_id"] == "fix:openbsd-openssh:patch"
    assert {"impact", "actions", "hosts", "cves", "advisories", "evidence_count"} <= set(d)
    assert "evidence" not in d  # evidence is large; counted here, listed by the exporters


def test_oldest_first_seen_per_host():
    old = dataclasses.replace(fx("f1"), first_found=datetime(2026, 1, 1, tzinfo=timezone.utc))
    new = dataclasses.replace(fx("f2", plugin=2), first_found=datetime(2026, 6, 1, tzinfo=timezone.utc))
    host = build_fix_packages([old, new])[0].hosts[0]
    assert host.oldest_first_found == old.first_found
