"""KEV and VPR feed the exploit component (weights unchanged)."""

from datetime import datetime, timezone

import pytest
from test_cluster import finding

from exposure_case.cluster import build_clusters
from exposure_case.scoring import WEIGHTS, score_cluster

NOW = datetime(2026, 11, 2, tzinfo=timezone.utc)


def exploit(*records):
    comps = {c.name: c for c in score_cluster(build_clusters(list(records))[0], 100, NOW).components}
    return comps["exploit"]


def quiet(fid="f1", asset="a1", **extra):
    """A finding with no exploit signal unless the test adds one."""
    return finding(fid, asset=asset, exploit_available=False, **extra)


def test_cisa_kev_is_the_top_level_even_without_other_flags():
    c = exploit(quiet(vpr={"on_cisa_kev": True, "score": 3.0}))
    assert c.raw == 1.0 and "KEV" in c.detail


def test_vpr_critical_band():
    c = exploit(quiet(vpr={"score": 9.2}))
    assert c.raw == pytest.approx(0.9) and "VPR 9.2" in c.detail


def test_vpr_high_band():
    assert exploit(quiet(vpr={"score": 7.5})).raw == pytest.approx(0.7)


def test_vpr_below_high_band_adds_nothing():
    assert exploit(quiet(vpr={"score": 6.9})).raw == 0.0


def test_public_exploit_still_scores_when_vpr_is_low():
    assert exploit(finding("f1", exploit_available=True, vpr={"score": 2.0})).raw == pytest.approx(0.6)


def test_highest_signal_across_findings_wins():
    c = exploit(quiet("f1", vpr={"score": 7.5}), quiet("f2", asset="a2", vpr={"on_cisa_kev": True}))
    assert c.raw == 1.0


def test_news_bonus_applies_on_top_and_is_capped():
    assert exploit(quiet(vpr={"score": 7.5}, in_the_news=True)).raw == pytest.approx(0.9)
    assert exploit(quiet(vpr={"on_cisa_kev": True}, in_the_news=True)).raw == 1.0


def test_malware_still_top_level():
    assert exploit(quiet(exploited_by_malware=True)).raw == 1.0


def test_no_signal_at_all():
    c = exploit(quiet())
    assert c.raw == 0.0 and c.detail == "no known exploit"


def test_weights_are_unchanged():
    assert dict(WEIGHTS) == {
        "severity": 30,
        "exploit": 25,
        "breadth": 15,
        "volume": 10,
        "age": 5,
        "unsupported": 5,
        "recurrence": 5,
        "patch": 5,
    }
