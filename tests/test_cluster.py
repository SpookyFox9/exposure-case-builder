import dataclasses

import pytest
from test_ingest import raw_record

from exposure_case.cluster import Cluster, build_clusters, is_patch_family, slugify
from exposure_case.ingest import parse_record


def finding(fid, plugin=100, asset="a1", family="General", severity="high", state="OPEN", name=None, **plugin_extra):
    raw = raw_record(finding_id=fid, state=state, severity=severity)
    raw["asset"]["uuid"] = asset
    raw["plugin"].update({"id": plugin, "family": family, "name": name or f"Plugin {plugin}", **plugin_extra})
    return parse_record(raw)


@pytest.mark.parametrize(
    "family,expected",
    [
        ("Red Hat Local Security Checks", True),
        ("Oracle Linux Local Security Checks", True),
        ("Windows : Microsoft Bulletins", True),
        ("CISCO", False),  # per-advisory; the fix view rolls these up by product
        ("General", False),
        ("Windows", False),
        ("Misc.", False),
        ("", False),
    ],
)
def test_is_patch_family(family, expected):
    assert is_patch_family(family) is expected


def test_slugify_is_stable_and_safe():
    assert slugify("Windows : Microsoft Bulletins") == "windows-microsoft-bulletins"
    assert slugify("  Red Hat / Local  ") == "red-hat-local"


def test_plugin_findings_group_into_one_cluster_across_assets():
    cs = build_clusters([finding("f1", asset="a1"), finding("f2", asset="a2"), finding("f3", asset="a2")])
    assert len(cs) == 1
    c = cs[0]
    assert c.cluster_id == "plugin:100" and c.kind == "plugin" and c.title == "Plugin 100"
    assert c.asset_count == 2 and len(c.active) == 3


def test_patch_family_plugins_merge_into_one_family_cluster():
    fam = "Red Hat Local Security Checks"
    cs = build_clusters(
        [
            finding("f1", plugin=1, family=fam),
            finding("f2", plugin=2, family=fam, asset="a2"),
            finding("f3", plugin=3, family="General"),
        ]
    )
    by_id = {c.cluster_id: c for c in cs}
    assert set(by_id) == {"family:red-hat-local-security-checks", "plugin:3"}
    family = by_id["family:red-hat-local-security-checks"]
    assert family.kind == "patch_family" and family.title == fam
    assert family.plugin_ids == (1, 2) and family.asset_count == 2


def test_info_findings_are_excluded():
    cs = build_clusters([finding("f1", severity="info"), finding("f2", plugin=2, severity="low")])
    assert [c.cluster_id for c in cs] == ["plugin:2"]


def test_fixed_findings_kept_for_timeline_but_not_active():
    cs = build_clusters([finding("f1"), finding("f2", state="FIXED", asset="a2")])
    c = cs[0]
    assert [r.finding_id for r in c.active] == ["f1"]
    assert [r.finding_id for r in c.fixed] == ["f2"]
    assert c.asset_count == 1  # fixed hosts do not count as affected


def test_cluster_with_only_fixed_findings_is_dropped():
    assert build_clusters([finding("f1", state="FIXED")]) == ()


def test_reopened_counts_as_active():
    c = build_clusters([finding("f1", state="REOPENED")])[0]
    assert len(c.active) == 1


def test_clusters_sorted_by_id_and_deterministic():
    recs = [finding("f1", plugin=9), finding("f2", plugin=2), finding("f3", plugin=5)]
    ids = [c.cluster_id for c in build_clusters(recs)]
    assert ids == sorted(ids)
    assert ids == [c.cluster_id for c in build_clusters(list(reversed(recs)))]


def test_evidence_lists_every_active_finding_sorted():
    c = build_clusters([finding("fb"), finding("fa", asset="a2"), finding("fx", state="FIXED")])[0]
    assert [e.record_id for e in c.evidence()] == ["fa", "fb"]
    assert all(e.source == "finding" for e in c.evidence())


def test_cluster_is_frozen():
    c = build_clusters([finding("f1")])[0]
    assert isinstance(c, Cluster)
    with pytest.raises(dataclasses.FrozenInstanceError):
        c.title = "x"  # type: ignore[misc]


def test_empty_input():
    assert build_clusters([]) == ()
