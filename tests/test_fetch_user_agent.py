"""Tenable's User-Agent guide: Integration/1.0 (VENDOR; PRODUCT; Build/VERSION) on every API call."""

import re

import pytest
from test_fetch_tenable import FakeTenable, client, ft, routes

FORMAT = re.compile(r"^Integration/1\.0 \([^;()]+; [^;()]+; Build/[0-9A-Za-z.+-]+\)$")


def test_default_user_agent_follows_tenables_format():
    assert FORMAT.match(ft.user_agent())


def test_default_names_the_project_not_a_person_or_employer():
    ua = ft.user_agent()
    assert "ExposureCaseBuilder" in ua and "Build/" in ua


def test_every_request_carries_the_user_agent(tmp_path):
    fake = FakeTenable(routes())
    ft.fetch(client(fake), tmp_path / "out", sleep=lambda s: None)
    assert fake.calls and all(FORMAT.match(headers["User-agent"]) for _, headers, _ in fake.calls)


def test_user_agent_never_contains_credentials():
    ua = ft.TenableClient("AKSECRET", "SKSECRET")._headers()["User-Agent"]
    assert "AKSECRET" not in ua and "SKSECRET" not in ua


def test_vendor_can_be_set_from_the_environment(monkeypatch):
    monkeypatch.setenv("TENABLE_UA_VENDOR", "Example Security Team")
    assert ft.user_agent().startswith("Integration/1.0 (Example Security Team; ")


@pytest.mark.parametrize("hostile", ["Evil; Corp", "A (B)", "line1\nX-Injected: 1", "x" * 500, "   ", ""])
def test_hostile_or_empty_vendor_cannot_break_the_header(monkeypatch, hostile):
    monkeypatch.setenv("TENABLE_UA_VENDOR", hostile)
    ua = ft.user_agent()
    assert FORMAT.match(ua) and "\n" not in ua and "\r" not in ua and len(ua) < 200


def test_explicit_arguments_override_the_defaults():
    assert ft.user_agent(vendor="ACME Industries", product="FancyIntegration", build="1.2.3") == (
        "Integration/1.0 (ACME Industries; FancyIntegration; Build/1.2.3)"
    )


def test_odd_build_strings_are_reduced_to_safe_characters():
    assert FORMAT.match(ft.user_agent(build="1.0; rm -rf /"))
