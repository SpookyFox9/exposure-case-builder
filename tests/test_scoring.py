from datetime import datetime, timezone

import pytest
from test_cluster import finding

from exposure_case.cluster import build_clusters
from exposure_case.scoring import (
    AGE_SATURATION_DAYS,
    WEIGHTS,
    as_of_from,
    fleet_size,
    rank_clusters,
    score_cluster,
)

NOW = datetime(2026, 11, 2, tzinfo=timezone.utc)


def one(records):
    return build_clusters(records)[0]


def components(records, fleet=100, as_of=NOW):
    s = score_cluster(one(records), fleet, as_of)
    return {c.name: c for c in s.components}, s


def test_weights_sum_to_100_and_are_positive():
    assert sum(w for _, w in WEIGHTS) == 100
    assert all(w > 0 for _, w in WEIGHTS)


def test_severity_uses_the_worst_active_finding():
    comps, _ = components([finding("f1", severity="low"), finding("f2", severity="critical", asset="a2")])
    assert comps["severity"].raw == 1.0 and comps["severity"].points == 30.0


@pytest.mark.parametrize("sev,raw", [("critical", 1.0), ("high", 0.75), ("medium", 0.4), ("low", 0.1)])
def test_severity_scale(sev, raw):
    comps, _ = components([finding("f1", severity=sev)])
    assert comps["severity"].raw == raw


def test_exploit_signal_levels():
    none, _ = components([finding("f1", exploit_available=False)])
    avail, _ = components([finding("f1", exploit_available=True)])
    malware, _ = components([finding("f1", exploit_available=True, exploited_by_malware=True)])
    news, _ = components([finding("f1", exploit_available=True, in_the_news=True)])
    assert none["exploit"].raw == 0.0
    assert avail["exploit"].raw == 0.6
    assert malware["exploit"].raw == 1.0
    assert news["exploit"].raw == pytest.approx(0.8)


def test_exploit_signal_is_capped_at_one():
    comps, _ = components([finding("f1", exploited_by_malware=True, in_the_news=True)])
    assert comps["exploit"].raw == 1.0


def test_breadth_grows_with_assets_and_is_bounded():
    few, _ = components([finding("f1", asset="a1")], fleet=100)
    many, _ = components([finding(f"f{i}", asset=f"a{i}") for i in range(50)], fleet=100)
    whole, _ = components([finding(f"f{i}", asset=f"a{i}") for i in range(100)], fleet=100)
    assert few["breadth"].raw < many["breadth"].raw < whole["breadth"].raw
    assert whole["breadth"].raw == pytest.approx(1.0)


def test_breadth_never_exceeds_one_when_fleet_is_undercounted():
    comps, _ = components([finding(f"f{i}", asset=f"a{i}") for i in range(10)], fleet=3)
    assert comps["breadth"].raw <= 1.0


def test_volume_counts_distinct_vulnerabilities_not_hosts():
    fam = "Red Hat Local Security Checks"
    one_plugin, _ = components([finding(f"f{i}", plugin=1, family=fam, asset=f"a{i}") for i in range(20)])
    many, _ = components([finding(f"g{i}", plugin=i, family=fam) for i in range(1, 21)])
    assert one_plugin["volume"].raw < many["volume"].raw <= 1.0


def test_volume_saturates():
    fam = "Red Hat Local Security Checks"
    comps, _ = components([finding(f"g{i}", plugin=i, family=fam) for i in range(1, 1500)])
    assert comps["volume"].raw == 1.0


def test_age_uses_oldest_active_finding_and_saturates():
    # first_found is 2026-05-24T09:01, so 7 whole days (and 15 hours) before 2026-06-01
    comps, _ = components([finding("f1")], as_of=datetime(2026, 6, 1, tzinfo=timezone.utc))
    assert comps["age"].raw == pytest.approx(7 / AGE_SATURATION_DAYS)
    assert comps["age"].weight == 5
    old, _ = components([finding("f1")], as_of=datetime(2030, 1, 1, tzinfo=timezone.utc))
    assert old["age"].raw == 1.0


def test_age_never_negative_when_as_of_precedes_first_found():
    comps, _ = components([finding("f1")], as_of=datetime(2020, 1, 1, tzinfo=timezone.utc))
    assert comps["age"].raw == 0.0


def test_unsupported_recurrence_and_patch_flags():
    comps, _ = components([
        finding("f1", unsupported_by_vendor=True, has_patch=True, state="REOPENED"),
        finding("f2", asset="a2", state="REOPENED"),
    ])
    assert comps["unsupported"].raw == 1.0
    assert comps["patch"].raw == 1.0
    assert comps["recurrence"].raw == pytest.approx(2 / 5)


def test_total_is_sum_of_points_and_within_bounds():
    _, s = components([finding("f1", severity="critical", exploited_by_malware=True, unsupported_by_vendor=True,
                               has_patch=True, state="REOPENED")], as_of=datetime(2030, 1, 1, tzinfo=timezone.utc))
    assert s.total == pytest.approx(sum(c.points for c in s.components))
    assert 0 < s.total <= 100


def test_every_component_has_a_human_readable_detail():
    _, s = components([finding("f1")])
    assert {c.name for c in s.components} == {name for name, _ in WEIGHTS}
    assert all(c.detail for c in s.components)


def test_score_to_dict_is_json_ready():
    _, s = components([finding("f1")])
    d = s.to_dict()
    assert set(d) == {"total", "components"} and d["components"][0].keys() >= {"name", "weight", "raw", "points", "detail"}


def test_rank_orders_by_score_then_id_and_numbers_from_one():
    recs = [finding("f1", plugin=2, severity="low"), finding("f2", plugin=1, severity="critical"),
            finding("f3", plugin=3, severity="low")]
    ranked = rank_clusters(build_clusters(recs), 100, NOW)
    assert [r.cluster.cluster_id for r in ranked] == ["plugin:1", "plugin:2", "plugin:3"]
    assert [r.rank for r in ranked] == [1, 2, 3]


def test_rank_is_independent_of_input_order():
    recs = [finding(f"f{i}", plugin=i, severity="medium") for i in range(1, 6)]
    a = [r.cluster.cluster_id for r in rank_clusters(build_clusters(recs), 100, NOW)]
    b = [r.cluster.cluster_id for r in rank_clusters(build_clusters(list(reversed(recs))), 100, NOW)]
    assert a == b


def test_fleet_size_counts_distinct_assets_including_info_and_fixed():
    recs = [finding("f1", asset="a1", severity="info"), finding("f2", asset="a2", state="FIXED"), finding("f3", asset="a2")]
    assert fleet_size(recs) == 2


def test_as_of_is_latest_last_found():
    recs = [finding("f1"), finding("f2")]
    assert as_of_from(recs) == max(r.last_found for r in recs)


def test_as_of_requires_records():
    with pytest.raises(ValueError):
        as_of_from([])
