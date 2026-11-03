import json
from pathlib import Path

import pytest
from test_make_sample import ms, rec

from exposure_case.ingest import load_findings

FIX_PLUGIN = {
    "solution": "Upgrade to OpenSSH 9.6 or later.",
    "cpe": ["cpe:/a:openbsd:openssh"],
    "cve": ["CVE-2023-48795"],
    "see_also": ["https://example.test/advisory"],
    "has_workaround": True,
    "patch_publication_date": "2023-12-18T00:00:00Z",
    "cvss3_base_score": 5.9,
    "epss_score": 0.42,
    "vpr": {
        "score": 8.1,
        "vpr_severity": "High",
        "on_cisa_kev": True,
        "exploit_code_maturity": "FUNCTIONAL",
        "drivers": "drop",
    },
}


@pytest.fixture
def trimmed(tmp_path):
    src = tmp_path / "src"
    (src / "chunks").mkdir(parents=True)
    record = rec("f-1", "asset-1", 100, **FIX_PLUGIN)
    record.update(
        {"last_fixed": "2026-10-01T00:00:00Z", "resurfaced_date": "2026-10-20T00:00:00Z", "time_taken_to_fix": 86400}
    )
    (src / "chunks" / "chunk_1.json").write_text(json.dumps([record]), encoding="utf-8")
    out = tmp_path / "out"
    ms.build_sample(src, out, n_plugins=1, n_notable=0)
    return out


def test_the_sample_keeps_what_the_fix_packages_and_scores_read(trimmed):
    (r,) = load_findings(trimmed)
    assert r.solution == FIX_PLUGIN["solution"] and r.cpe == ("cpe:/a:openbsd:openssh",)
    assert r.cves == ("CVE-2023-48795",) and r.see_also == ("https://example.test/advisory",)
    assert r.has_workaround is True and r.patch_published is not None
    assert r.cvss3_base_score == 5.9 and r.epss_score == 0.42
    assert r.vpr_score == 8.1 and r.on_cisa_kev is True and r.exploit_code_maturity == "FUNCTIONAL"
    assert r.last_fixed is not None and r.resurfaced is not None and r.fix_seconds == 86400


def test_plugin_output_and_unread_fields_are_still_dropped(trimmed):
    (raw,) = json.loads(Path(trimmed / "chunks" / "chunk_1.json").read_text(encoding="utf-8"))
    assert "output" not in raw and "indexed" not in raw
    assert "description" not in raw["plugin"] and "xrefs" not in raw["plugin"]
    assert "drivers" not in raw["plugin"]["vpr"]
