"""Whole-flow test: fetch (fake Tenable) -> real MCP server -> case -> export -> disposition. No network."""

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from test_fetch_tenable import EXPORT_ID, FakeTenable, client, ft

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample"
TIMEOUT_S = 120


def tenable_serving_the_sample() -> FakeTenable:
    """A fake Tenable whose export is the committed sample, so the fetch script runs for real."""
    chunk = json.loads((SAMPLE / "chunks" / "chunk_1.json").read_text(encoding="utf-8"))
    plugins = json.loads((SAMPLE / "plugins.json").read_text(encoding="utf-8"))
    return FakeTenable(
        {
            ("POST", "/vulns/export"): {"export_uuid": EXPORT_ID},
            ("GET", f"/vulns/export/{EXPORT_ID}/status"): {"status": "FINISHED", "chunks_available": [1]},
            ("GET", f"/vulns/export/{EXPORT_ID}/chunks/1"): chunk,
            ("GET", "/workbenches/vulnerabilities?date_range=90"): plugins,
        }
    )


def text(result) -> str:
    return "".join(c.text for c in result.content)


async def analyst_session(data_dir: Path, exports: Path, log: Path) -> dict:
    env = {
        **os.environ,
        "EXPOSURE_CASE_DATA": str(data_dir),
        "EXPOSURE_CASE_EXPORTS": str(exports),
        "EXPOSURE_CASE_DISPOSITIONS": str(log),
    }
    params = StdioServerParameters(command=sys.executable, args=["-m", "exposure_case.server"], env=env)
    out: dict = {}
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()

        async def call(name: str, **arguments):
            return await session.call_tool(name, arguments)

        queue = json.loads(text(await call("case_queue", top_n=1)))
        case_id = queue["threats"][0]["case_id"]
        out["case_id"] = case_id
        out["findings"] = json.loads(text(await call("findings", item_id=case_id, limit=5)))
        out["case"] = json.loads(text(await call("case_file", case_id=case_id)))
        out["unapproved_write"] = await call("export", item_id=case_id, write=True)
        out["export"] = json.loads(text(await call("export", item_id=case_id, write=True, confirm=True)))
        out["disposition"] = json.loads(
            text(
                await call(
                    "record_disposition",
                    item_id=case_id,
                    analyst="analyst-1",
                    disposition="assigned",
                    note="sent to the owning team",
                    confirm=True,
                )
            )
        )
        out["queue_after"] = json.loads(text(await call("case_queue", top_n=50, hide_dispositioned=True)))
    return out


@pytest.fixture(scope="module")
def flow(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("e2e")
    fetched = ft.fetch(client(tenable_serving_the_sample()), tmp / "fetched", sleep=lambda s: None)
    result = asyncio.run(asyncio.wait_for(analyst_session(fetched, tmp / "exports", tmp / "log.jsonl"), TIMEOUT_S))
    return {**result, "tmp": tmp, "fetched": fetched}


@pytest.mark.e2e
def test_the_fetched_export_is_what_the_server_analysed(flow):
    fetched_ids = {
        r["finding_id"] for r in json.loads((flow["fetched"] / "chunks" / "chunk_1.json").read_text("utf-8"))
    }
    cited = {f["finding_id"] for f in flow["findings"]["findings"]}
    assert cited and cited <= fetched_ids


@pytest.mark.e2e
def test_the_case_carries_its_evidence_and_limits(flow):
    case = flow["case"]
    assert case["case_id"] == flow["case_id"] and case["score"]["components"] and case["limitations"]
    assert case["evidence_ids_total"] >= len(case["evidence_ids"]) > 0


@pytest.mark.e2e
def test_writing_needs_approval_and_then_produces_the_files(flow):
    assert flow["unapproved_write"].is_error and "confirm" in text(flow["unapproved_write"])
    exports = flow["tmp"] / "exports"
    names = flow["export"]["written"]
    assert {Path(n).suffix for n in names} == {".md", ".json", ".csv"}
    assert all((exports / n).exists() for n in names)


@pytest.mark.e2e
def test_the_exported_json_cites_only_fetched_findings(flow):
    exports = flow["tmp"] / "exports"
    json_name = next(n for n in flow["export"]["written"] if n.endswith(".json"))
    exported = json.loads((exports / json_name).read_text(encoding="utf-8"))
    fetched_ids = {
        r["finding_id"] for r in json.loads((flow["fetched"] / "chunks" / "chunk_1.json").read_text("utf-8"))
    }
    assert set(exported["evidence_ids"]) <= fetched_ids and exported["disposition"] is None


@pytest.mark.e2e
def test_the_decision_is_logged_once_and_hides_the_case(flow):
    lines = (flow["tmp"] / "log.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["item_id"] == flow["case_id"]
    queue = flow["queue_after"]
    assert flow["case_id"] not in [i["case_id"] for i in queue["threats"]]
    assert queue["hidden_dispositioned"]["threats"] == 1


@pytest.mark.e2e
def test_no_absolute_paths_reach_the_model(flow):
    blob = json.dumps([flow["export"], flow["disposition"], flow["case"]])
    assert str(flow["tmp"]) not in blob


def test_every_test_has_exactly_one_category(request):
    from conftest import CATEGORIES

    for item in request.session.items:
        marks = [name for name in CATEGORIES if item.get_closest_marker(name)]
        assert len(marks) >= 1, item.nodeid
