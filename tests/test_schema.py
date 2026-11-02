import dataclasses

import pytest

from exposure_case.schema import Evidence

pytestmark = pytest.mark.unit


def test_evidence_serialises_to_source_and_record_id():
    assert Evidence(source="finding", record_id="F1").to_dict() == {"source": "finding", "record_id": "F1"}


def test_evidence_is_frozen():
    ev = Evidence(source="finding", record_id="F1")
    with pytest.raises(dataclasses.FrozenInstanceError):
        ev.record_id = "F2"  # type: ignore[misc]


@pytest.mark.parametrize("source,record_id", [("", "F1"), ("   ", "F1"), ("finding", ""), ("finding", "  ")])
def test_evidence_must_name_a_source_and_a_record(source, record_id):
    with pytest.raises(ValueError, match="evidence"):
        Evidence(source=source, record_id=record_id)


@pytest.mark.parametrize("source,record_id", [(None, "F1"), ("finding", None), (1, "F1"), ("finding", 7)])
def test_evidence_fields_must_be_text(source, record_id):
    with pytest.raises(ValueError, match="evidence"):
        Evidence(source=source, record_id=record_id)  # type: ignore[arg-type]
