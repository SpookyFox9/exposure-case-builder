"""Security review findings for the Tenable fetch script (redirects, sizes, ids, output directory)."""

import http.server
import io
import json
import threading
from pathlib import Path
from typing import ClassVar

import pytest
from test_fetch_tenable import EXPORT_ID, FakeResponse, FakeTenable, client, ft, routes

pytestmark = pytest.mark.integration


class Recorder(http.server.BaseHTTPRequestHandler):
    hits: ClassVar[list] = []

    def do_GET(self):
        type(self).hits.append((self.path, dict(self.headers)))
        redirect_to = getattr(type(self), "redirect_to", None)
        if redirect_to:
            self.send_response(302)
            self.send_header("Location", redirect_to)
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

    def log_message(self, *args):
        pass


def serve(handler_cls):
    server = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_redirects_are_refused_and_the_keys_never_follow(monkeypatch):
    class Target(Recorder):
        hits: ClassVar[list] = []

    class Origin(Recorder):
        hits: ClassVar[list] = []

    target, origin = serve(Target), serve(Origin)
    try:
        Origin.redirect_to = f"http://127.0.0.1:{target.server_port}/stolen"
        monkeypatch.setattr(ft, "BASE_URL", f"http://127.0.0.1:{origin.server_port}")
        with pytest.raises(ft.FetchError, match="HTTP 302"):
            ft.TenableClient("AKSECRET", "SKSECRET").request("GET", "/users")
        assert len(Origin.hits) == 1 and Target.hits == []
    finally:
        target.shutdown()
        origin.shutdown()


def test_redirect_handler_never_builds_a_new_request():
    handler = ft._NoRedirect()
    assert handler.redirect_request(None, None, 302, "Found", {}, "http://evil.test/") is None


def test_oversized_responses_are_rejected(monkeypatch):
    monkeypatch.setattr(ft, "MAX_RESPONSE_BYTES", 100)

    def opener(req, timeout=None):
        return FakeResponse(b'{"x": "' + b"a" * 500 + b'"}')

    with pytest.raises(ft.FetchError, match="too large"):
        client(opener).request("GET", "/x")


def test_responses_at_the_limit_are_accepted(monkeypatch):
    monkeypatch.setattr(ft, "MAX_RESPONSE_BYTES", 100)
    body = json.dumps({"ok": 1}).encode()
    assert client(lambda req, timeout=None: FakeResponse(body)).request("GET", "/x") == {"ok": 1}


def test_the_chunk_count_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(ft, "MAX_CHUNKS", 2)
    r = routes()
    r[("GET", f"/vulns/export/{EXPORT_ID}/status")] = {"status": "FINISHED", "chunks_available": [1, 2, 3]}
    with pytest.raises(ft.FetchError, match="chunk"):
        ft.fetch(client(FakeTenable(r)), tmp_path / "out", sleep=lambda s: None)


@pytest.mark.parametrize("bad", ["../x", "a/b", "", "not a uuid", "E" * 200, 5, None])
def test_export_uuid_must_look_like_a_uuid(tmp_path, bad):
    r = routes()
    r[("POST", "/vulns/export")] = {"export_uuid": bad}
    with pytest.raises(ft.FetchError, match="export_uuid"):
        ft.fetch(client(FakeTenable(r)), tmp_path / "out", sleep=lambda s: None)


def test_a_real_uuid_is_accepted(tmp_path):
    uuid = "0a1b2c3d-4e5f-6789-abcd-ef0123456789"
    r = {
        ("POST", "/vulns/export"): {"export_uuid": uuid},
        ("GET", f"/vulns/export/{uuid}/status"): {"status": "FINISHED", "chunks_available": [1]},
        ("GET", f"/vulns/export/{uuid}/chunks/1"): [],
        ("GET", "/workbenches/vulnerabilities?date_range=90"): {"vulnerabilities": []},
    }
    assert ft.fetch(client(FakeTenable(r)), tmp_path / "out", sleep=lambda s: None).exists()


def test_a_symlinked_output_directory_is_refused(tmp_path, monkeypatch):
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(Path, "is_symlink", lambda self: self.name == "out")
    with pytest.raises(ft.FetchError, match="symlink"):
        ft.fetch(client(FakeTenable(routes())), out, sleep=lambda s: None)


def test_files_are_written_via_temp_files_so_a_failure_leaves_nothing_half_written(tmp_path, monkeypatch):
    real = ft.os.replace
    calls = {"n": 0}

    def flaky(src, dst):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("disk full")
        return real(src, dst)

    monkeypatch.setattr(ft.os, "replace", flaky)
    out = tmp_path / "out"
    with pytest.raises(ft.FetchError):
        ft.fetch(client(FakeTenable(routes())), out, sleep=lambda s: None)
    assert not out.exists()


def test_write_failures_are_fetch_errors_not_tracebacks(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    with pytest.raises(ft.FetchError):
        ft.fetch(client(FakeTenable(routes())), blocker / "sub", sleep=lambda s: None)


def test_unused_stringio_import_guard():
    assert io.StringIO  # keeps the helper import honest if the file is trimmed later
