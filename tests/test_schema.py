import dataclasses

import pytest

from exposure_case.schema import Evidence, Finding


def _evidence():
    return (Evidence(source="finding", record_id="F1"),)


def _finding(**overrides):
    base = {
        "id": "X1", "detector": "E1", "subject": "plugin:10114",
        "score": 1.0, "rationale": "r", "evidence": _evidence(),
    }
    return Finding(**{**base, **overrides})


def test_finding_requires_evidence():
    with pytest.raises(ValueError, match="evidence"):
        _finding(evidence=())


def test_finding_rejects_blank_record_id():
    with pytest.raises(ValueError, match="record_id"):
        _finding(evidence=(Evidence(source="finding", record_id=""),))


def test_finding_rejects_blank_source():
    with pytest.raises(ValueError, match="source"):
        _finding(evidence=(Evidence(source="", record_id="F1"),))


def test_finding_to_dict_lists_evidence():
    d = _finding(score=2.5).to_dict()
    assert d["evidence"] == [{"source": "finding", "record_id": "F1"}]
    assert d["score"] == 2.5
    assert d["subject"] == "plugin:10114"


def test_finding_is_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        _finding().score = 9.0  # type: ignore[misc]


def test_finding_coerces_evidence_list_to_tuple():
    f = _finding(evidence=list(_evidence()))
    assert isinstance(f.evidence, tuple)


@pytest.mark.parametrize("bad", [float("nan"), float("inf")])
def test_finding_rejects_non_finite_score(bad):
    with pytest.raises(ValueError, match="finite"):
        _finding(score=bad)
