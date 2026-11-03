from pathlib import Path

import pytest
from test_coverage import hot, quiet

from exposure_case.coverage import COVERAGE_NOTE
from exposure_case.service import ServiceError, Workspace

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample"
VIM = "cpe:/a:vim:vim"
BASH = "cpe:/a:gnu:bash"


@pytest.fixture
def ws(tmp_path):
    return Workspace.load(SAMPLE, exports_dir=tmp_path / "exports", dispositions_path=tmp_path / "d.jsonl")


@pytest.fixture
def small(tmp_path):
    """Three packages: two with urgent findings (sharing host a1) and one without."""
    records = (
        hot("v1", asset="a1", plugin=1, cpe=VIM, solution="Upgrade vim."),
        hot("b1", asset="a1", plugin=2, cpe=BASH, solution="Upgrade bash."),
        hot("b2", asset="a2", plugin=3, cpe=BASH, solution="Upgrade bash."),
        quiet("n1", asset="a3", plugin=4, cpe="cpe:/a:nginx:nginx", solution="Upgrade nginx."),
    )
    return Workspace(records, {}, tmp_path / "exports", tmp_path / "d.jsonl")


def test_default_order_is_still_the_score_order(ws):
    scores = [i["score"] for i in ws.fix_queue(top_n=20)["items"]]
    assert scores == sorted(scores, reverse=True)
    assert "coverage_note" not in ws.fix_queue() and ws.fix_queue()["order"] == "score"


def test_every_row_carries_its_coverage_step_or_none(ws):
    for row in ws.fix_queue(top_n=50)["items"]:
        assert "coverage" in row
        assert row["coverage"] is None or row["coverage"]["package_id"] == row["package_id"]


def test_coverage_order_follows_the_steps(ws):
    items = ws.fix_queue(top_n=50, order="coverage")["items"]
    steps = [i["coverage"]["step"] for i in items if i["coverage"]]
    assert steps == list(range(1, len(steps) + 1))
    assert [i["position"] for i in items] == list(range(1, len(items) + 1))
    flags = [i["coverage"] is not None for i in items]
    assert flags == sorted(flags, reverse=True)  # packages without urgent findings come last


def test_coverage_order_keeps_the_score_rank_on_each_row(ws):
    score_rank = {i["package_id"]: i["rank"] for i in ws.fix_queue(top_n=50)["items"]}
    rows = ws.fix_queue(top_n=50, order="coverage")["items"]
    assert rows and all(row["rank"] == score_rank[row["package_id"]] for row in rows)


@pytest.mark.parametrize("order", ["", "Coverage", "risk", None, 1, ["coverage"]])
def test_unknown_order_is_a_service_error(ws, order):
    with pytest.raises(ServiceError, match="order"):
        ws.fix_queue(order=order)


def test_the_note_is_only_sent_with_the_coverage_order_and_says_what_it_assumes(ws):
    answer = ws.fix_queue(order="coverage")
    assert answer["coverage_note"] == COVERAGE_NOTE
    for phrase in ("every earlier step", "hidden or dispositioned", "not that a host is secure", "heuristic"):
        assert phrase in COVERAGE_NOTE


def test_the_note_warns_that_steps_cannot_be_reordered_or_resummed():
    # Rehearsal 2026-11-03: the model moved steps 5-7 first and added their counts; those only hold after 1-4.
    for phrase in ("reordering steps", "a subset", "does not give"):
        assert phrase in COVERAGE_NOTE, phrase


def test_fix_package_includes_its_coverage_step(ws):
    row = next(i for i in ws.fix_queue(top_n=50, order="coverage")["items"] if i["coverage"])
    assert ws.fix_package(row["package_id"])["coverage"] == row["coverage"]


def test_a_package_without_urgent_findings_has_no_coverage(small):
    rows = {r["package_id"]: r for r in small.fix_queue(order="coverage")["items"]}
    assert rows["fix:nginx-nginx:patch"]["coverage"] is None
    assert small.fix_package("fix:nginx-nginx:patch")["coverage"] is None
    assert [r["package_id"] for r in small.fix_queue(order="coverage")["items"]][-1] == "fix:nginx-nginx:patch"


def test_steps_on_a_small_export_are_exact(small):
    rows = small.fix_queue(order="coverage")["items"]
    stepped = [r["coverage"] for r in rows if r["coverage"]]
    assert [(c["package_id"], c["hosts_cleared"], c["cumulative_hosts_cleared"]) for c in stepped] == [
        ("fix:gnu-bash:patch", 1, 1),  # clears a2 (a1 still has vim)
        ("fix:vim-vim:patch", 1, 2),
    ]
    assert stepped[0]["urgent_hosts_total"] == 2


def test_hiding_a_dispositioned_package_keeps_its_step_numbers_and_the_note(small):
    small.record_disposition("fix:gnu-bash:patch", "analyst-1", "assigned", "ticket opened", confirm=True)
    answer = small.fix_queue(order="coverage", hide_dispositioned=True)
    ids = [r["package_id"] for r in answer["items"]]
    assert "fix:gnu-bash:patch" not in ids and answer["hidden_dispositioned"] == 1
    vim = next(r for r in answer["items"] if r["package_id"] == "fix:vim-vim:patch")
    assert vim["coverage"]["step"] == 2  # the gap is visible, not renumbered
    assert answer["coverage_note"] == COVERAGE_NOTE


def test_the_sample_order_accounts_for_every_urgent_host(ws):
    rows = ws.fix_queue(top_n=50, order="coverage")["items"]
    last = [r["coverage"] for r in rows if r["coverage"]][-1]
    assert last["cumulative_hosts_cleared"] == last["urgent_hosts_total"]
