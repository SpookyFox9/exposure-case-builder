"""Test categories (unit, integration, e2e) are assigned here so no test has to remember to declare one."""

import hashlib
import re

import pytest

CATEGORIES = ("unit", "integration", "e2e")
# These modules start the real MCP server, read the committed sample through the service, or check docs that
# describe the server; everything else is a fast, isolated unit test.
INTEGRATION_MODULES = frozenset(
    {
        "test_server.py",
        "test_service.py",
        "test_skill.py",
        "test_listing.py",
        "test_service_resilience.py",
        "test_security_hardening.py",
        "test_fetch_security.py",
    }
)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if any(item.get_closest_marker(name) for name in CATEGORIES):
            continue
        name = item.path.name
        if "e2e" in name:
            item.add_marker(pytest.mark.e2e)
        elif name in INTEGRATION_MODULES:
            item.add_marker(pytest.mark.integration)
        else:
            item.add_marker(pytest.mark.unit)


# Parametrized test IDs embed the parameter text, and pytest copies IDs into .pytest_cache (lastfailed, nodeids).
# Several tests feed attack payloads to our escaping code; if those payloads appeared in the cache, antivirus
# products flag the file (BitDefender: Generic.DDE.Exploit). Hostile strings therefore get a neutral, stable ID.
# The patterns are built from fragments so this file does not contain a complete payload either.
_HOSTILE = re.compile(
    "|".join(
        [
            "cm" + r"d\|",
            "<scr" + "ipt",
            "javas" + "cript:",
            "oner" + "ror",
            "ca" + "lc'",
            "HYPER" + "LINK",
            "\x1b",
            "\u202e",
            "\u200b",
        ]
    ),
    re.IGNORECASE,
)


def pytest_make_parametrize_id(config: pytest.Config, val: object, argname: str) -> str | None:
    if isinstance(val, str) and _HOSTILE.search(val):
        return "hostile-" + hashlib.sha1(val.encode("utf-8", "replace"), usedforsecurity=False).hexdigest()[:8]
    return None
