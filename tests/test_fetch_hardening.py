"""Hardening tests for the Tenable fetch script (from code review)."""

import pytest
from test_fetch_tenable import FakeTenable, client, ft, routes


def routes_with(status_body=None):
    r = routes()
    if status_body is not None:
        r[("GET", "/vulns/export/E1/status")] = status_body
    return r


def run(tmp_path, status_body):
    fake = FakeTenable(routes_with(status_body))
    return ft.fetch(client(fake), tmp_path / "out", sleep=lambda s: None)


@pytest.mark.parametrize("bad", ["../../plugins", "..\\x", 1.5, True, None, -1, 0])
def test_chunk_ids_must_be_positive_ints(tmp_path, bad):
    with pytest.raises(ft.FetchError, match="chunk"):
        run(tmp_path, {"status": "FINISHED", "chunks_available": [bad]})
    assert not (tmp_path / "plugins.json").exists()


def test_chunks_available_must_be_a_list(tmp_path):
    with pytest.raises(ft.FetchError, match="chunk"):
        run(tmp_path, {"status": "FINISHED", "chunks_available": "12"})


@pytest.mark.parametrize("body", [[1, 2], None, "x"])
def test_non_dict_status_is_fetch_error(tmp_path, body):
    fake = FakeTenable(routes_with(body))
    fake.routes[("GET", "/vulns/export/E1/status")] = lambda: body
    with pytest.raises(ft.FetchError, match="status"):
        ft.fetch(client(fake), tmp_path / "out", sleep=lambda s: None)


def test_failed_chunks_are_an_error(tmp_path):
    with pytest.raises(ft.FetchError, match="failed"):
        run(tmp_path, {"status": "FINISHED", "chunks_available": [1], "chunks_failed": [2]})


def test_empty_chunk_list_is_an_error(tmp_path):
    with pytest.raises(ft.FetchError, match="no chunks"):
        run(tmp_path, {"status": "FINISHED", "chunks_available": []})


def test_partial_failure_cleans_up_so_retry_works(tmp_path):
    r = routes()
    del r[("GET", "/vulns/export/E1/chunks/2")]  # chunk 2 -> 404
    out = tmp_path / "out"
    with pytest.raises(ft.FetchError):
        ft.fetch(client(FakeTenable(r)), out, sleep=lambda s: None)
    assert not out.exists()
    ft.fetch(client(FakeTenable(routes())), out, sleep=lambda s: None)
    assert (out / "chunks" / "chunk_2.json").exists()


@pytest.mark.parametrize(
    "exc", [TimeoutError("t"), ConnectionResetError("r"), UnicodeDecodeError("utf-8", b"", 0, 1, "x")]
)
def test_transport_errors_become_fetch_error(exc):
    def boom(req, timeout=None):
        raise exc

    with pytest.raises(ft.FetchError):
        client(boom).request("GET", "/x")


def test_client_repr_and_vars_hide_keys():
    c = client(FakeTenable({}))
    assert "AK" not in repr(c) and "SK" not in repr(c)
    with pytest.raises(TypeError):
        vars(c)


def test_keys_are_stripped_and_validated(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "  a  ")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "b")
    assert ft.keys_from_env() == ("a", "b")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "b;c")
    with pytest.raises(ft.FetchError, match="TENABLE_SECRET_KEY"):
        ft.keys_from_env()


def test_main_returns_1_and_leaks_nothing_on_failure(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "AKSECRET")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "SKSECRET")
    real = ft.TenableClient
    monkeypatch.setattr(ft, "TenableClient", lambda a, s: real(a, s, opener=FakeTenable({})))
    assert ft.main(["--out", str(tmp_path / "o")]) == 1
    captured = capsys.readouterr()
    assert "AKSECRET" not in captured.out + captured.err
    assert "SKSECRET" not in captured.out + captured.err


def test_main_rejects_non_positive_chunk_assets():
    with pytest.raises(SystemExit):
        ft.main(["--chunk-assets", "0"])
