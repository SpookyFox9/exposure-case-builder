import dataclasses
from datetime import datetime

import pytest

from insider_case.schema import Evidence, Event, Finding


def _evidence():
    return (Evidence(source="logon", record_id="L1"),)


def test_event_is_frozen():
    e = Event(source="logon", record_id="L1", ts=datetime(2026, 1, 1, 9), user="U1", pc="PC1", summary="Logon")
    with pytest.raises(dataclasses.FrozenInstanceError):
        e.user = "U2"  # type: ignore[misc]


def test_finding_requires_evidence():
    with pytest.raises(ValueError, match="evidence"):
        Finding(id="F1", detector="D1", user="U1", date="2026-01-01", score=1.0, rationale="x", evidence=())


def test_finding_rejects_blank_record_id():
    with pytest.raises(ValueError, match="record_id"):
        Finding(
            id="F1", detector="D1", user="U1", date="2026-01-01", score=1.0, rationale="x",
            evidence=(Evidence(source="logon", record_id=""),),
        )


def test_finding_to_dict_lists_evidence():
    f = Finding(id="F1", detector="D1", user="U1", date="2026-01-01", score=2.5, rationale="r", evidence=_evidence())
    d = f.to_dict()
    assert d["evidence"] == [{"source": "logon", "record_id": "L1"}]
    assert d["score"] == 2.5


def test_finding_is_frozen():
    f = Finding(id="F1", detector="D1", user="U1", date="2026-01-01", score=1.0, rationale="r", evidence=_evidence())
    with pytest.raises(dataclasses.FrozenInstanceError):
        f.score = 9.0  # type: ignore[misc]


def test_finding_coerces_evidence_list_to_tuple():
    f = Finding(id="F1", detector="D1", user="U1", date="2026-01-01", score=1.0, rationale="r",
                evidence=list(_evidence()))  # type: ignore[arg-type]
    assert isinstance(f.evidence, tuple)


@pytest.mark.parametrize("bad", [float("nan"), float("inf")])
def test_finding_rejects_non_finite_score(bad):
    with pytest.raises(ValueError, match="finite"):
        Finding(id="F1", detector="D1", user="U1", date="2026-01-01", score=bad, rationale="r", evidence=_evidence())


def test_finding_rejects_blank_source():
    with pytest.raises(ValueError, match="source"):
        Finding(id="F1", detector="D1", user="U1", date="2026-01-01", score=1.0, rationale="r",
                evidence=(Evidence(source="", record_id="L1"),))
