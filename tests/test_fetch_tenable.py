import importlib.util
import io
import json
import urllib.error
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "fetch_tenable.py"
spec = importlib.util.spec_from_file_location("fetch_tenable", SCRIPT)
ft = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ft)


EXPORT_ID = "0a1b2c3d-4e5f-6789-abcd-ef0123456789"


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeTenable:
    """Records requests and answers from a route table: {(method, path): body or callable}."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, req, timeout=None):
        key = (req.get_method(), req.full_url.replace(ft.BASE_URL, ""))
        self.calls.append((key, dict(req.header_items()), req.data))
        answer = self.routes.get(key)
        if answer is None:
            raise urllib.error.HTTPError(req.full_url, 404, "nf", {}, None)
        if callable(answer):
            answer = answer()
        return FakeResponse(json.dumps(answer).encode())


def routes(status_sequence=("FINISHED",)):
    seq = iter(status_sequence)
    return {
        ("POST", "/vulns/export"): {"export_uuid": EXPORT_ID},
        ("GET", "/vulns/export/0a1b2c3d-4e5f-6789-abcd-ef0123456789/status"): lambda: {
            "status": next(seq),
            "chunks_available": [1, 2],
        },
        ("GET", "/vulns/export/0a1b2c3d-4e5f-6789-abcd-ef0123456789/chunks/1"): [{"finding_id": "a"}],
        ("GET", "/vulns/export/0a1b2c3d-4e5f-6789-abcd-ef0123456789/chunks/2"): [{"finding_id": "b"}],
        ("GET", "/workbenches/vulnerabilities?date_range=90"): {"vulnerabilities": [{"plugin_id": 1}]},
    }


def client(opener):
    return ft.TenableClient("AK", "SK", opener=opener)


def test_fetch_writes_chunks_and_plugins(tmp_path):
    fake = FakeTenable(routes())
    ft.fetch(client(fake), tmp_path / "out", sleep=lambda s: None)
    out = tmp_path / "out"
    assert json.loads((out / "chunks" / "chunk_1.json").read_text()) == [{"finding_id": "a"}]
    assert json.loads((out / "chunks" / "chunk_2.json").read_text()) == [{"finding_id": "b"}]
    assert json.loads((out / "plugins.json").read_text())["vulnerabilities"][0]["plugin_id"] == 1


def test_fetch_polls_until_finished(tmp_path):
    fake = FakeTenable(routes(("QUEUED", "PROCESSING", "FINISHED")))
    ft.fetch(client(fake), tmp_path / "out", sleep=lambda s: None)
    polls = [c for c in fake.calls if c[0][1].endswith("/status")]
    assert len(polls) == 3


def test_fetch_fails_on_export_error(tmp_path):
    fake = FakeTenable(routes(("ERROR",)))
    with pytest.raises(ft.FetchError, match="ERROR"):
        ft.fetch(client(fake), tmp_path / "out", sleep=lambda s: None)


def test_fetch_times_out(tmp_path):
    fake = FakeTenable(routes(("PROCESSING",) * 50))
    with pytest.raises(ft.FetchError, match="timed out"):
        ft.fetch(client(fake), tmp_path / "out", sleep=lambda s: None, max_polls=3)


def test_fetch_refuses_non_empty_output_dir(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "x").write_text("keep")
    with pytest.raises(ft.FetchError, match="not empty"):
        ft.fetch(client(FakeTenable(routes())), out, sleep=lambda s: None)


def test_requests_carry_keys_in_header_only():
    fake = FakeTenable(routes())
    client(fake).request("POST", "/vulns/export", {"num_assets": 50})
    _key, headers, data = fake.calls[0]
    assert headers["X-apikeys"] == "accessKey=AK;secretKey=SK"
    assert b"AK" not in data and b"SK" not in data


def test_http_error_message_never_contains_keys():
    fake = FakeTenable({})
    with pytest.raises(ft.FetchError) as exc:
        client(fake).request("GET", "/nope")
    msg = str(exc.value)
    assert "404" in msg and "/nope" in msg
    assert "AK" not in msg.replace("accessKey", "") and "SK" not in msg.replace("secretKey", "")


def test_keys_from_env_requires_both(monkeypatch):
    monkeypatch.delenv("TENABLE_ACCESS_KEY", raising=False)
    monkeypatch.setenv("TENABLE_SECRET_KEY", "x")
    with pytest.raises(ft.FetchError, match="TENABLE_ACCESS_KEY"):
        ft.keys_from_env()


def test_keys_from_env_returns_pair(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "a")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "b")
    assert ft.keys_from_env() == ("a", "b")
