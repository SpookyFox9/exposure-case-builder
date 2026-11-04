"""SECURITY.md says undeclared tool arguments are ignored, so a misspelled flag can never turn a write on."""

import asyncio
from pathlib import Path

import pytest

from exposure_case.server import build_server
from exposure_case.service import Workspace

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample"

pytestmark = pytest.mark.integration


def _call(server, name, arguments):
    try:
        result = asyncio.run(server.call_tool(name, arguments))
    except Exception as exc:  # the SDK may raise the tool error instead of returning it
        return str(exc)
    return "".join(getattr(c, "text", "") for c in getattr(result, "content", result))


def test_a_misspelled_confirm_flag_does_not_write(tmp_path):
    log = tmp_path / "d.jsonl"
    server = build_server(Workspace.load(SAMPLE, exports_dir=tmp_path / "e", dispositions_path=log))
    args = {"item_id": "plugin:77823", "analyst": "t", "disposition": "assigned", "note": "n", "confirmed": True}
    message = _call(server, "record_disposition", args)
    assert "confirm" in message and not log.exists()
    _call(server, "export", {"item_id": "plugin:77823", "write": True, "Confirm": True})
    assert not (tmp_path / "e").exists() or not any((tmp_path / "e").iterdir())


def test_an_unknown_argument_on_a_read_tool_is_ignored(tmp_path):
    server = build_server(Workspace.load(SAMPLE, exports_dir=tmp_path / "e", dispositions_path=tmp_path / "d.jsonl"))
    assert '"hosts": 154' in _call(server, "fleet_summary", {"bogus": 1})
