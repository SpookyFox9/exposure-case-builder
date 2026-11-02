"""Fix and risk fields carried by the export (solution, VPR, KEV, EPSS, CPE, fix dates)."""

from datetime import timezone

import pytest
from test_ingest import raw_record

from exposure_case.ingest import parse_record


def rec(plugin_extra=None, **top):
    raw = raw_record(**top)
    raw["plugin"].update(plugin_extra or {})
    return parse_record(raw)


def test_defaults_when_fields_absent():
    r = parse_record(raw_record())
    assert r.solution == "" and r.see_also == () and r.cves == () and r.cpe == ()
    assert r.vpr_score is None and r.vpr_severity == "" and r.on_cisa_kev is False
    assert r.exploit_code_maturity == "" and r.epss_score is None and r.cvss3_base_score is None
    assert r.patch_published is None and r.has_workaround is False
    assert r.last_fixed is None and r.resurfaced is None and r.fix_seconds is None


def test_solution_references_and_product_fields():
    r = rec(
        {
            "solution": "  Upgrade to OpenSSH 9.6 or later.  ",
            "see_also": ["https://example.test/a", "https://example.test/b"],
            "cve": ["CVE-2023-48795"],
            "cpe": ["cpe:/a:openbsd:openssh"],
            "has_workaround": True,
            "cvss3_base_score": 5.9,
            "epss_score": 1.163,
            "patch_publication_date": "2023-12-18T00:00:00Z",
        }
    )
    assert r.solution == "Upgrade to OpenSSH 9.6 or later."
    assert r.see_also == ("https://example.test/a", "https://example.test/b")
    assert r.cves == ("CVE-2023-48795",) and r.cpe == ("cpe:/a:openbsd:openssh",)
    assert r.has_workaround is True and r.cvss3_base_score == 5.9 and r.epss_score == 1.163
    assert r.patch_published.tzinfo == timezone.utc and r.patch_published.year == 2023


def test_vpr_object_is_flattened():
    r = rec({"vpr": {"score": 8.4, "vpr_severity": "HIGH", "on_cisa_kev": True, "exploit_code_maturity": "FUNCTIONAL"}})
    assert (r.vpr_score, r.vpr_severity, r.on_cisa_kev, r.exploit_code_maturity) == (8.4, "HIGH", True, "FUNCTIONAL")


def test_finding_level_fix_dates():
    r = rec(
        None,
        last_fixed="2026-10-25T09:03:01.280Z",
        resurfaced_date="2026-09-27T08:44:13.944Z",
        time_taken_to_fix=600932,
    )
    assert r.last_fixed.year == 2026 and r.resurfaced.month == 9
    assert r.fix_seconds == 600932


@pytest.mark.parametrize(
    "plugin_extra",
    [
        {"solution": {"a": 1}},
        {"solution": 5},
        {"see_also": "https://x.test"},
        {"cve": "CVE-1"},
        {"cpe": [1, None, {"x": 1}]},
        {"vpr": "high"},
        {"vpr": ["x"]},
        {"epss_score": "high"},
        {"cvss3_base_score": True},
        {"patch_publication_date": "nonsense"},
        {"has_workaround": "yes"},
    ],
)
def test_malformed_optional_fields_fall_back_to_defaults_without_raising(plugin_extra):
    r = rec(plugin_extra)
    assert r.solution == "" or isinstance(r.solution, str)
    assert r.on_cisa_kev is False and r.vpr_score is None
    assert r.epss_score is None and r.cvss3_base_score is None
    assert r.has_workaround is False


def test_non_string_list_items_are_dropped():
    r = rec({"see_also": ["https://ok.test", 5, None], "cve": ["CVE-1", {"x": 1}], "cpe": ["cpe:/a:v:p", 3]})
    assert r.see_also == ("https://ok.test",) and r.cves == ("CVE-1",) and r.cpe == ("cpe:/a:v:p",)


@pytest.mark.parametrize("bad", ["soon", 12.5, True, -5, None])
def test_bad_fix_seconds_become_none(bad):
    assert rec(None, time_taken_to_fix=bad).fix_seconds is None


def test_bad_optional_timestamps_become_none_but_required_ones_still_raise():
    assert rec(None, last_fixed="garbage", resurfaced_date=7).last_fixed is None
    from exposure_case.ingest import IngestError

    with pytest.raises(IngestError):
        parse_record(raw_record(first_found="garbage"))


def test_vpr_kev_requires_a_real_boolean():
    assert rec({"vpr": {"on_cisa_kev": "true"}}).on_cisa_kev is False
    assert rec({"vpr": {"on_cisa_kev": 1}}).on_cisa_kev is False


def test_vpr_score_out_of_range_is_ignored():
    assert rec({"vpr": {"score": 99}}).vpr_score is None
    assert rec({"vpr": {"score": -1}}).vpr_score is None
