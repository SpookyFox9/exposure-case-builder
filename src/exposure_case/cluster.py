"""Group findings into cases.

Hybrid rule (decided 2026-11-02):
  * Patch-type families become ONE case per family ("this fleet is behind on Red Hat patches"),
    because hundreds of near-identical per-advisory plugins describe the same fix action.
  * Every other plugin is its own case ("fix weak SSH ciphers on these hosts").

Info-level findings never form cases. FIXED findings are kept on a case only to draw its timeline.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from .ingest import FindingRecord
from .schema import Evidence

PATCH_FAMILY_SUFFIX = "Local Security Checks"
# CISCO is deliberately NOT here (user decision, 2026-11-02): its advisories stay separate cases, and the
# fix view (fixes.py) rolls them up by product (IOS, NX-OS, ...).
PATCH_FAMILY_NAMES = frozenset({"Windows : Microsoft Bulletins"})


def is_patch_family(family: str) -> bool:
    return family.endswith(PATCH_FAMILY_SUFFIX) or family in PATCH_FAMILY_NAMES


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


@dataclass(frozen=True)
class Cluster:
    """One case: a patch family or a single plugin, with its active and fixed findings."""

    cluster_id: str
    kind: str  # "patch_family" | "plugin"
    title: str
    family: str
    plugin_ids: tuple[int, ...]
    active: tuple[FindingRecord, ...]
    fixed: tuple[FindingRecord, ...]

    @property
    def asset_uuids(self) -> frozenset[str]:
        return frozenset(r.asset_uuid for r in self.active)

    @property
    def asset_count(self) -> int:
        return len(self.asset_uuids)

    def evidence(self) -> tuple[Evidence, ...]:
        """One evidence pointer per active finding, in finding_id order."""
        return tuple(r.evidence() for r in sorted(self.active, key=lambda r: r.finding_id))


def _key(record: FindingRecord) -> tuple[str, str, str]:
    """(cluster_id, kind, title) for a record."""
    if is_patch_family(record.plugin_family):
        return f"family:{slugify(record.plugin_family)}", "patch_family", record.plugin_family
    return f"plugin:{record.plugin_id}", "plugin", record.plugin_name or f"Plugin {record.plugin_id}"


def build_clusters(records: Iterable[FindingRecord]) -> tuple[Cluster, ...]:
    """Cluster findings; return cases that still have at least one active finding, sorted by id."""
    groups: dict[str, list[FindingRecord]] = defaultdict(list)
    meta: dict[str, tuple[str, str]] = {}
    for record in records:
        if record.severity == "info":
            continue
        cluster_id, kind, title = _key(record)
        groups[cluster_id].append(record)
        meta.setdefault(cluster_id, (kind, title))

    clusters: list[Cluster] = []
    for cluster_id in sorted(groups):
        members = sorted(groups[cluster_id], key=lambda r: r.finding_id)
        active = tuple(r for r in members if r.state != "FIXED")
        if not active:
            continue
        kind, title = meta[cluster_id]
        clusters.append(
            Cluster(
                cluster_id=cluster_id,
                kind=kind,
                title=title,
                family=active[0].plugin_family,
                plugin_ids=tuple(sorted({r.plugin_id for r in active})),
                active=active,
                fixed=tuple(r for r in members if r.state == "FIXED"),
            )
        )
    return tuple(clusters)
