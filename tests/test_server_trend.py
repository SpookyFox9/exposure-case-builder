import asyncio
import json
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from exposure_case.server import resolve_baseline
from exposure_case.trend import CATEGORIES

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "sample"
TIMEOUT_S = 90


def text(result) -> str:
    return "".join(c.text for c in result.content)


def data(result):
    return json.loads(text(result))


def _make_baseline(target: Path) -> Path:
    import importlib.util

    spec = importlib.util.spec_from_file_location("make_baseline_for_server", ROOT / "scripts" / "make_baseline.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    assert module.main([str(SAMPLE), str(target)]) == 0
    return target


async def scenario(tmp: Path, baseline: Path) -> dict:
    base_env = {
        **{k: v for k, v in os.environ.items() if k != "EXPOSURE_CASE_BASELINE"},
        "EXPOSURE_CASE_DATA": str(SAMPLE),
        "EXPOSURE_CASE_EXPORTS": str(tmp / "exports"),
        "EXPOSURE_CASE_DISPOSITIONS": str(tmp / "d.jsonl"),
    }
    out: dict = {}
    for name, env in (("plain", base_env), ("with_baseline", {**base_env, "EXPOSURE_CASE_BASELINE": str(baseline)})):
        params = StdioServerParameters(command=sys.executable, args=["-m", "exposure_case.server"], env=env)
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            out[name] = {
                "tools": {t.name: t for t in (await session.list_tools()).tools},
                "summary": data(await session.call_tool("trend_diff", {})),
                "page": data(await session.call_tool("trend_diff", {"category": "fixed_recorded", "limit": 3})),
                "bad_category": await session.call_tool("trend_diff", {"category": "fixed"}),
                "bad_limit": await session.call_tool("trend_diff", {"limit": 0}),
            }
    return out


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("trend-server")
    return asyncio.run(asyncio.wait_for(scenario(tmp, _make_baseline(tmp / "baseline")), TIMEOUT_S))


def test_the_tool_exists_is_read_only_and_lists_its_categories(run):
    tool = run["plain"]["tools"]["trend_diff"]
    assert tool.annotations is not None and tool.annotations.read_only_hint is True
    categories = set(tool.input_schema["properties"]["category"]["anyOf"][0]["enum"])
    assert categories == set(CATEGORIES)
    assert not {"path", "baseline", "directory"} & set(tool.input_schema["properties"])


def test_without_a_baseline_the_server_says_how_to_configure_one(run):
    answer = run["plain"]["summary"]
    assert answer["configured"] is False and "EXPOSURE_CASE_BASELINE" in answer["note"]


def test_with_a_baseline_the_summary_and_pages_work_over_mcp(run):
    got = run["with_baseline"]
    assert got["summary"]["configured"] is True and got["summary"]["synthetic"] is True
    assert got["summary"]["findings"]["fixed_recorded"] > 0
    assert got["page"]["category"] == "fixed_recorded" and 0 < len(got["page"]["rows"]) <= 3
    assert all(row["finding_id"] and "plugin_name" not in row for row in got["page"]["rows"])


def test_bad_arguments_are_errors_over_mcp(run):
    for name in ("plain", "with_baseline"):
        assert run[name]["bad_category"].is_error and run[name]["bad_limit"].is_error


def test_no_absolute_paths_in_tool_output(run):
    blob = json.dumps(run["with_baseline"]["summary"])
    assert str(ROOT) not in blob and "baseline" in blob


@pytest.mark.parametrize(
    "env,expected",
    [({}, None), ({"EXPOSURE_CASE_BASELINE": ""}, None)],
)
def test_resolve_baseline_is_optional(env, expected):
    assert resolve_baseline(env) is expected


def test_resolve_baseline_needs_an_absolute_path(tmp_path):
    assert resolve_baseline({"EXPOSURE_CASE_BASELINE": str(tmp_path)}) == tmp_path.resolve()
    with pytest.raises(ValueError, match="absolute"):
        resolve_baseline({"EXPOSURE_CASE_BASELINE": "relative/dir"})


def test_the_server_refuses_to_start_on_a_bad_baseline(tmp_path):
    import subprocess

    proc = subprocess.run(
        [sys.executable, "-m", "exposure_case.server"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env={**os.environ, "EXPOSURE_CASE_DATA": str(SAMPLE), "EXPOSURE_CASE_BASELINE": str(tmp_path / "nope")},
    )
    assert proc.returncode == 1 and proc.stdout == "" and "baseline" in proc.stderr.lower()


def test_the_instructions_say_ids_from_the_export_are_untrusted_text():
    from exposure_case.server import INSTRUCTIONS

    text_ = " ".join(INSTRUCTIONS.lower().split())
    assert "finding ids, asset ids and scan ids" in text_ and "untrusted" in text_
