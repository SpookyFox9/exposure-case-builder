"""Small helpers shared across modules, kept in one place so they cannot drift apart."""

from __future__ import annotations

from collections.abc import Iterable

# Tenable's severities, worst first. Every module that orders or validates severities uses this one tuple.
SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")


def worst_severity(severities: Iterable[str]) -> str:
    """The most severe value present, or 'info' when there are none."""
    present = set(severities)
    return next((s for s in SEVERITY_ORDER if s in present), "info")


def plural(n: int, word: str, many: str | None = None) -> str:
    """'1 host' / '3 hosts'; pass ``many`` for irregular plurals ('vulnerabilities')."""
    return f"{n:,} {word}" if n == 1 else f"{n:,} {many or word + 's'}"
