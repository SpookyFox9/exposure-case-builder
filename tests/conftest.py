"""Test categories (unit, integration, e2e) are assigned here so no test has to remember to declare one."""

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
