"""Quality review 2026-11-03: one throttled (429) or temporarily unavailable (5xx) answer during a long pull lost the
whole download. Retries are bounded, honour a capped Retry-After, and never repeat the job-creating POST on 5xx."""

import urllib.error

import pytest
from test_fetch_tenable import EXPORT_ID, FakeTenable, ft, routes

pytestmark = pytest.mark.unit

STATUS = ("GET", f"/vulns/export/{EXPORT_ID}/status")
CREATE = ("POST", "/vulns/export")


def failing_then(answer, codes, retry_after=None):
    remaining = list(codes)

    def respond():
        if remaining:
            headers = {"Retry-After": retry_after} if retry_after is not None else {}
            raise urllib.error.HTTPError("https://cloud.tenable.com", remaining.pop(0), "busy", headers, None)
        return answer() if callable(answer) else answer

    return respond


def make_client(fake, sleeps):
    return ft.TenableClient("a" * 64, "b" * 64, opener=fake, sleep=sleeps.append)


def test_throttling_and_unavailable_answers_are_retried_with_backoff(tmp_path):
    r = routes()
    r[STATUS] = failing_then(r[STATUS], [429, 503, 502])
    sleeps: list[float] = []
    ft.fetch(make_client(FakeTenable(r), sleeps), tmp_path / "out", sleep=lambda s: None)
    assert (tmp_path / "out" / "plugins.json").exists()
    assert len(sleeps) == 3 and sleeps == sorted(sleeps) and all(0 < s <= ft.MAX_RETRY_WAIT_S for s in sleeps)


def test_retry_after_is_honoured_but_capped(tmp_path):
    r = routes()
    r[STATUS] = failing_then(r[STATUS], [429], retry_after="3600")
    sleeps: list[float] = []
    ft.fetch(make_client(FakeTenable(r), sleeps), tmp_path / "out", sleep=lambda s: None)
    assert sleeps == [ft.MAX_RETRY_WAIT_S]


def test_retries_are_bounded(tmp_path):
    r = routes()
    r[STATUS] = failing_then(r[STATUS], [503] * 50)
    sleeps: list[float] = []
    with pytest.raises(ft.FetchError, match="503"):
        ft.fetch(make_client(FakeTenable(r), sleeps), tmp_path / "out", sleep=lambda s: None)
    assert len(sleeps) == ft.MAX_ATTEMPTS - 1


def test_the_job_creating_post_is_not_repeated_on_a_server_error(tmp_path):
    r = routes()
    r[CREATE] = failing_then(r[CREATE], [503])
    fake, sleeps = FakeTenable(r), []
    with pytest.raises(ft.FetchError, match="503"):
        ft.fetch(make_client(fake, sleeps), tmp_path / "out", sleep=lambda s: None)
    assert sleeps == [] and sum(1 for key, *_ in fake.calls if key == CREATE) == 1


def test_other_errors_are_not_retried(tmp_path):
    r = routes()
    r[STATUS] = failing_then(r[STATUS], [403])
    sleeps: list[float] = []
    with pytest.raises(ft.FetchError, match="403"):
        ft.fetch(make_client(FakeTenable(r), sleeps), tmp_path / "out", sleep=lambda s: None)
    assert sleeps == []


def test_a_non_ascii_retry_after_falls_back_to_backoff(tmp_path):
    r = routes()
    r[STATUS] = failing_then(r[STATUS], [429], retry_after="\u00b2")  # a superscript two passes str.isdigit()
    sleeps: list[float] = []
    ft.fetch(make_client(FakeTenable(r), sleeps), tmp_path / "out", sleep=lambda s: None)
    assert sleeps == [float(ft.RETRY_BASE_WAIT_S)]
