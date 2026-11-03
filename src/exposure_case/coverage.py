"""Coverage order: which fix packages to apply, in what order, so hosts stop carrying urgent findings soonest.

Findings are disjoint across fix packages (each active finding is in exactly one), so counting findings cleared
adds up the same in any order. The overlap is in hosts: one host usually has urgent findings in several packages
and is clear only once every one of them is applied. This module orders packages greedily by how many hosts each
one newly brings to zero urgent findings, given the packages already placed.

An *urgent* finding is active, not informational, and critical, on the CISA KEV list, exploited by malware, or has
a public exploit. "Cleared" means no urgent finding in this export; lower-severity findings may remain and hosts
that were not scanned are invisible. The order is a heuristic, not the shortest plan: clearing a host needs all
of its packages, which is not classic set cover and has no approximation guarantee. Tenable's data does not say one
update replaces another, so a step means "apply every listed action in this package".

Deterministic, no ML. Ties on hosts cleared go to the package that removes more urgent findings, then to the one
with fewer distinct fix actions (effort), then to the package id. Effort is never a divisor.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .fixes import FixPackage, RankedPackage
from .ingest import FindingRecord

URGENT_SEVERITY = "critical"
ORDERS = ("score", "coverage")
COVERAGE_NOTE = (
    "Coverage order: greedy, by hosts newly brought to zero urgent findings (critical, CISA KEV, exploited by "
    "malware or a public exploit) if every listed action in this package and in every earlier step is applied; "
    "the figures assume that, including for packages hidden or dispositioned in this view. 'Cleared' means no "
    "urgent finding in this export, not that a host is secure or that lower-severity findings are gone; hosts "
    "that were not scanned are not counted. It is a heuristic, not the shortest plan. Each step's figures depend "
    "on every earlier step, so reordering steps or adding up a subset does not give that plan's figures. "
    "Tenable's data does not say one update replaces another."
)


def is_urgent(record: FindingRecord) -> bool:
    """Active, not informational, and critical, on KEV, exploited by malware, or with a public exploit."""
    if record.state == "FIXED" or record.severity == "info":
        return False
    return (
        record.severity == URGENT_SEVERITY
        or record.on_cisa_kev
        or record.exploited_by_malware
        or record.exploit_available
    )


@dataclass(frozen=True)
class CoverageStep:
    """One position in the coverage order: apply every listed action in ``package_id`` at this step."""

    step: int
    package_id: str
    hosts_cleared: int  # hosts that reach zero urgent findings once this package AND every earlier step is applied
    cumulative_hosts_cleared: int
    urgent_hosts_total: int  # hosts with at least one urgent finding anywhere in the export
    urgent_findings: int  # urgent findings this package removes
    actions: int  # distinct Tenable fix actions in the package

    def to_dict(self) -> dict[str, int | str]:
        return {
            "step": self.step,
            "package_id": self.package_id,
            "hosts_cleared": self.hosts_cleared,
            "cumulative_hosts_cleared": self.cumulative_hosts_cleared,
            "urgent_hosts_total": self.urgent_hosts_total,
            "urgent_findings": self.urgent_findings,
            "actions": self.actions,
        }


@dataclass(frozen=True)
class _Candidate:
    package_id: str
    actions: int
    urgent_findings: int
    per_host: tuple[tuple[str, int], ...]  # (asset_uuid, urgent findings of this package on that host)


def _candidate(package: FixPackage) -> _Candidate | None:
    counts = Counter(r.asset_uuid for r in package.active if is_urgent(r))
    if not counts:
        return None
    return _Candidate(package.package_id, package.impact.actions, sum(counts.values()), tuple(sorted(counts.items())))


def _gain(candidate: _Candidate, remaining: dict[str, int]) -> int:
    """Hosts that would reach zero urgent findings: all of the host's remaining urgent findings are in this package."""
    return sum(1 for host, n in candidate.per_host if remaining[host] == n)


def _priority(candidate: _Candidate, gain: int) -> tuple[int, int, int, str]:
    """Sort key, smallest first: most hosts cleared, then most urgent findings removed, then fewest fix actions
    (effort, a tie-break only), then package id so the order is deterministic."""
    return -gain, -candidate.urgent_findings, candidate.actions, candidate.package_id


def _index(candidates: Sequence[_Candidate]) -> tuple[dict[str, int], dict[str, list[tuple[str, int]]]]:
    """Per host: urgent findings still open, and which candidates hold them as (package_id, count)."""
    remaining: dict[str, int] = {}
    holders: dict[str, list[tuple[str, int]]] = {}
    for c in candidates:
        for host, n in c.per_host:
            remaining[host] = remaining.get(host, 0) + n
            holders.setdefault(host, []).append((c.package_id, n))
    return remaining, holders


def _apply(
    best: _Candidate,
    remaining: dict[str, int],
    holders: dict[str, list[tuple[str, int]]],
    gains: dict[str, int],
) -> None:
    """Take ``best`` out of the pool and update only the gains of packages that share one of its hosts.

    ``remaining`` and ``gains`` are scratch state local to one ``coverage_order`` call; nothing outside sees them
    change. A package's gain can rise as well as fall (its host is cleared once the others are gone), so the
    gain is recomputed for the affected packages rather than assumed to only shrink.
    """
    del gains[best.package_id]
    for host, taken in best.per_host:
        before = remaining[host]
        remaining[host] = before - taken
        for package_id, needs in holders[host]:
            if package_id in gains:
                gains[package_id] += (remaining[host] == needs) - (before == needs)


def coverage_order(packages: Iterable[FixPackage]) -> tuple[CoverageStep, ...]:
    """Greedy order over packages that have urgent findings; packages without any get no step."""
    candidates = [c for c in (_candidate(p) for p in packages) if c is not None]
    by_id = {c.package_id: c for c in candidates}
    remaining, holders = _index(candidates)
    gains = {c.package_id: _gain(c, remaining) for c in candidates}
    total = len(remaining)
    steps: list[CoverageStep] = []
    cleared = 0
    while gains:
        best = by_id[min(gains, key=lambda pid: _priority(by_id[pid], gains[pid]))]
        gain = gains[best.package_id]
        cleared += gain
        steps.append(
            CoverageStep(
                step=len(steps) + 1,
                package_id=best.package_id,
                hosts_cleared=gain,
                cumulative_hosts_cleared=cleared,
                urgent_hosts_total=total,
                urgent_findings=best.urgent_findings,
                actions=best.actions,
            )
        )
        _apply(best, remaining, holders, gains)
    return tuple(steps)


def in_coverage_order(ranked: Sequence[RankedPackage], steps: Sequence[CoverageStep]) -> tuple[RankedPackage, ...]:
    """Packages in coverage-step order, then the packages with no urgent findings in their given (score) order."""
    by_id = {r.package.package_id: r for r in ranked}
    placed = {s.package_id for s in steps}
    stepped = [by_id[s.package_id] for s in steps if s.package_id in by_id]
    rest = [r for r in ranked if r.package.package_id not in placed]
    return (*stepped, *rest)
