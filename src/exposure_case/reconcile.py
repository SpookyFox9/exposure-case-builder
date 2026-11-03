"""Trust check: compare our per-plugin host counts with Tenable's own plugin-level counts.

There is no answer key for this data, so agreement with the workbench numbers is the evidence that
clustering did not lose or invent findings. Mismatches are reported, not asserted: on the
2026-11-02 export 4,636 of 4,677 comparable plugins matched Tenable's count, either as distinct hosts
(4,622) or as finding instances (14 more, e.g. one finding per host and port). The other 41 all had the
export below Tenable's count (cause unverified; the workbench saw 164 assets, the export has 160).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .ingest import FindingRecord, PluginInfo


@dataclass(frozen=True)
class Mismatch:
    plugin_id: int
    export_assets: int
    export_findings: int
    workbench_count: int


@dataclass(frozen=True)
class Reconciliation:
    compared: int
    exact: int  # equals distinct hosts OR finding instances
    instances_only: int  # subset of exact: matched finding instances but not distinct hosts
    not_in_workbench: int
    mismatches: tuple[Mismatch, ...]

    @property
    def export_below_workbench(self) -> int:
        return sum(max(m.export_assets, m.export_findings) < m.workbench_count for m in self.mismatches)

    @property
    def export_above_workbench(self) -> int:
        return sum(min(m.export_assets, m.export_findings) > m.workbench_count for m in self.mismatches)

    def to_dict(self) -> dict:
        return {
            "compared": self.compared,
            "exact": self.exact,
            "matched_on_instances_only": self.instances_only,
            "mismatch_count": len(self.mismatches),
            "not_in_workbench": self.not_in_workbench,
            "export_below_workbench": self.export_below_workbench,
            "export_above_workbench": self.export_above_workbench,
            "largest_gaps": [
                {
                    "plugin_id": m.plugin_id,
                    "export_assets": m.export_assets,
                    "export_findings": m.export_findings,
                    "workbench_count": m.workbench_count,
                }
                for m in sorted(self.mismatches, key=lambda m: -(m.workbench_count - m.export_findings))[:10]
            ],
        }


def reconcile(records: Iterable[FindingRecord], plugin_info: Mapping[int, PluginInfo]) -> Reconciliation:
    """Non-fixed hosts and finding instances per plugin (every severity) versus the workbench ``count``."""
    hosts: dict[int, set[str]] = defaultdict(set)
    instances: dict[int, int] = defaultdict(int)
    for record in records:
        if record.state != "FIXED":
            hosts[record.plugin_id].add(record.asset_uuid)
            instances[record.plugin_id] += 1

    exact = instances_only = missing = 0
    mismatches: list[Mismatch] = []
    for plugin_id in sorted(hosts):
        info = plugin_info.get(plugin_id)
        if info is None:
            missing += 1
        elif info.count == len(hosts[plugin_id]):
            exact += 1
        elif info.count == instances[plugin_id]:
            exact += 1
            instances_only += 1
        else:
            mismatches.append(Mismatch(plugin_id, len(hosts[plugin_id]), instances[plugin_id], info.count))
    return Reconciliation(
        compared=exact + len(mismatches),
        exact=exact,
        instances_only=instances_only,
        not_in_workbench=missing,
        mismatches=tuple(mismatches),
    )


QUALITY_NOTE = (
    "Counts are plugins, not findings: per plugin, the export's host (or finding) count is compared with Tenable's "
    "own plugin-level count. A mismatch means the counts differ for that plugin, not that its findings are wrong. "
    "export_below_workbench and export_above_workbench count the mismatches where both export counts are below, "
    "or both above, Tenable's; any other mismatch has Tenable's count between the two. The cause of the gaps is "
    "unverified."
)


def quality_summary(rec: Reconciliation) -> dict[str, Any]:
    """The reconciliation counts as fleet_summary reports them, labelled with their unit and direction."""
    return {
        "compared_unit": "plugins",
        "compared": rec.compared,
        "exact": rec.exact,
        "mismatch_count": len(rec.mismatches),
        "export_below_workbench": rec.export_below_workbench,
        "export_above_workbench": rec.export_above_workbench,
        "not_in_workbench": rec.not_in_workbench,
        "note": QUALITY_NOTE,
    }
