"""The tool layer's engine: load an export once, answer every question as capped, JSON-ready data.

``server.py`` is a thin wrapper over this. Nothing here accepts a file path from a caller: the data,
export and disposition locations are fixed when the workspace is created. Errors a caller can fix are
``ServiceError`` (the server shows their message); anything else is a bug and stays opaque.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import disposition as dlog
from .case import (
    SCOPE_NOTE,
    CaseFile,
    PackageView,
    build_case_file,
    build_package_view,
    case_facts,
    priority_reasons,
)
from .cluster import Cluster, build_clusters
from .export import (
    ExportError,
    case_hosts_csv,
    case_json,
    case_markdown,
    package_actions_csv,
    package_hosts_csv,
    package_json,
    package_markdown,
    write_case_export,
    write_package_export,
)
from .fixes import SEVERITY_ORDER, FixPackage, RankedPackage, build_fix_packages, rank_packages
from .ingest import FindingRecord, IngestError, load_findings, load_plugin_info
from .links import Links, link_cases_and_fixes
from .reconcile import reconcile
from .scoring import RankedCluster, as_of_from, fleet_size, rank_clusters

QUEUE_KINDS = {"threats": "plugin", "backlogs": "patch_family"}
MAX_TOP_N = 50
MAX_LIST = 500
MAX_PAGE = 100
MAX_VULNS = 100
MAX_INLINE_CHARS = 60_000
MAX_SOLUTION_CHARS = 500


class ServiceError(ValueError):
    """A problem the caller can understand and fix."""


def _int(value: Any, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ServiceError(f"{name} must be an integer from {low} to {high}")
    return value


def _shorten(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit].rstrip() + "\u2026"


def _worst(by_severity: dict[str, int]) -> str:
    return next((s for s in SEVERITY_ORDER if by_severity.get(s)), "info")


class Workspace:
    """One loaded export with its cases, fix packages, links and rankings."""

    def __init__(self, records: tuple[FindingRecord, ...], plugin_info: dict, exports_dir: Path,
                 dispositions_path: Path) -> None:
        self.records = records
        self.exports_dir = Path(exports_dir)
        self.dispositions_path = Path(dispositions_path)
        self.fleet = fleet_size(records)
        self.as_of = as_of_from(records)
        cases, packages = build_clusters(records), build_fix_packages(records)
        self.links: Links = link_cases_and_fixes(cases, packages)
        self.ranked_cases: tuple[RankedCluster, ...] = rank_clusters(cases, self.fleet, self.as_of)
        self.ranked_packages: tuple[RankedPackage, ...] = rank_packages(packages, self.fleet, self.as_of)
        self._cases = {r.cluster.cluster_id: r for r in self.ranked_cases}
        self._packages = {r.package.package_id: r for r in self.ranked_packages}
        self._reconciliation = reconcile(records, plugin_info).to_dict() if plugin_info else None
        self._log_cache: tuple[tuple[int, int] | None, dict[str, dlog.Disposition], int] | None = None
        self._case_files: dict[str, CaseFile] = {}
        self._package_views: dict[str, PackageView] = {}

    @classmethod
    def load(cls, data_dir: str | Path, exports_dir: str | Path, dispositions_path: str | Path) -> Workspace:
        data = Path(data_dir)
        if not data.is_dir():
            raise ServiceError(f"data directory not found: {data}")
        try:
            return cls(load_findings(data), load_plugin_info(data), Path(exports_dir), Path(dispositions_path))
        except IngestError as exc:
            raise ServiceError(f"cannot load the export: {exc}") from None

    # --- helpers ---

    def _log_state(self) -> tuple[dict[str, dlog.Disposition], int]:
        """Latest disposition per item and the count of unreadable log lines; cached until the file changes."""
        try:
            stat = self.dispositions_path.stat()
            key: tuple[int, int] | None = (stat.st_mtime_ns, stat.st_size)
        except OSError:
            key = None
        if self._log_cache is None or self._log_cache[0] != key:
            try:
                entries, bad = dlog.read_dispositions_lenient(self.dispositions_path)
            except dlog.DispositionError as exc:
                raise ServiceError(str(exc)) from None
            self._log_cache = (key, dlog.latest_by_item(entries), len(bad))
        return self._log_cache[1], self._log_cache[2]

    def _latest(self) -> dict[str, dlog.Disposition]:
        return self._log_state()[0]

    def _case_view(self, case_id: str) -> CaseFile:
        if case_id not in self._case_files:
            self._case_files[case_id] = build_case_file(self._case(case_id), self.links, self.as_of)
        return self._case_files[case_id]

    def _package_view(self, package_id: str) -> PackageView:
        if package_id not in self._package_views:
            self._package_views[package_id] = build_package_view(self._package(package_id), self.links, self.as_of)
        return self._package_views[package_id]

    def _case(self, case_id: str) -> RankedCluster:
        if not isinstance(case_id, str) or case_id not in self._cases:
            raise ServiceError("unknown case_id; list cases with case_queue")
        return self._cases[case_id]

    def _package(self, package_id: str) -> RankedPackage:
        if not isinstance(package_id, str) or package_id not in self._packages:
            raise ServiceError("unknown package_id; list packages with fix_queue")
        return self._packages[package_id]

    def _item(self, item_id: str) -> tuple[str, Cluster | FixPackage]:
        if isinstance(item_id, str) and item_id in self._cases:
            return "case", self._cases[item_id].cluster
        if isinstance(item_id, str) and item_id in self._packages:
            return "fix_package", self._packages[item_id].package
        raise ServiceError("unknown id; use a case_id from case_queue or a package_id from fix_queue")

    # --- summaries ---

    def fleet_summary(self) -> dict:
        active = [r for r in self.records if r.severity != "info" and r.state != "FIXED"]
        kinds = Counter(r.cluster.kind for r in self.ranked_cases)
        types = Counter(r.package.fix_type for r in self.ranked_packages)
        summary: dict[str, Any] = {
            "as_of": self.as_of.isoformat(),
            "hosts": self.fleet,
            "findings_total": len(self.records),
            "active_findings": len(active),
            "by_severity": dict(Counter(r.severity for r in active)),
            "states": dict(Counter(r.state for r in self.records)),
            "kev_findings": sum(r.on_cisa_kev for r in active),
            "cases": {"total": len(self.ranked_cases), "threats": kinds["plugin"], "backlogs": kinds["patch_family"]},
            "fix_packages": {"total": len(self.ranked_packages), **dict(types)},
            "dispositions_recorded": len(self._latest()),
            "notes": [
                "Hostnames, IP addresses and similar identifiers are masked in this dataset; treat them as opaque.",
                "Findings of severity info are not part of any case.",
            ],
        }
        warnings = self._log_state()[1]
        if warnings:
            summary["log_warnings"] = warnings
            summary["notes"].append(
                f"{warnings} unreadable line(s) in the disposition log were skipped; see EXPOSURE_CASE_DISPOSITIONS.")
        if self._reconciliation:
            summary["data_quality"] = {k: self._reconciliation[k] for k in
                                       ("compared", "exact", "mismatch_count", "not_in_workbench")}
        return summary

    def _case_row(self, ranked: RankedCluster, position: int, latest: dict) -> dict:
        case = ranked.cluster
        facts = case_facts(list(case.active), self.as_of)
        entry = latest.get(case.cluster_id)
        return {
            "position": position, "rank": ranked.rank, "case_id": case.cluster_id, "title": case.title,
            "kind": case.kind, "score": round(ranked.score.total, 1), "worst_severity": _worst(facts["by_severity"]),
            "hosts": facts["hosts"], "vulnerabilities": facts["vulnerabilities"], "findings": facts["findings"],
            "kev_findings": facts["kev_findings"], "why": list(priority_reasons(ranked.score)),
            "fix_packages": [link.other_id for link in self.links.fixes_for(case.cluster_id)[:3]],
            "disposition": entry.to_dict() if entry else None,
        }

    def case_queue(self, kind: str = "both", top_n: int = 10, hide_dispositioned: bool = False) -> dict:
        if kind not in ("both", *QUEUE_KINDS):
            raise ServiceError("kind must be both, threats or backlogs")
        top_n = _int(top_n, "top_n", 1, MAX_TOP_N)
        latest = self._latest()

        def rows(case_kind: str) -> list[dict]:
            chosen = [r for r in self.ranked_cases if r.cluster.kind == case_kind
                      and not (hide_dispositioned and r.cluster.cluster_id in latest)][:top_n]
            return [self._case_row(r, i, latest) for i, r in enumerate(chosen, start=1)]

        if kind == "both":
            return {"threats": rows("plugin"), "backlogs": rows("patch_family"), "as_of": self.as_of.isoformat()}
        return {"kind": kind, "items": rows(QUEUE_KINDS[kind]), "as_of": self.as_of.isoformat()}

    def fix_queue(self, top_n: int = 10, hide_dispositioned: bool = False) -> dict:
        top_n = _int(top_n, "top_n", 1, MAX_TOP_N)
        latest = self._latest()
        chosen = [r for r in self.ranked_packages
                  if not (hide_dispositioned and r.package.package_id in latest)][:top_n]
        items = []
        for position, r in enumerate(chosen, start=1):
            p = r.package
            entry = latest.get(p.package_id)
            items.append({
                "position": position, "rank": r.rank, "package_id": p.package_id, "title": p.title,
                "fix_type": p.fix_type, "score": round(r.score.total, 1), "hosts": p.impact.hosts,
                "vulnerabilities": p.impact.plugins, "actions": p.impact.actions, "findings": p.impact.findings,
                "by_severity": p.impact.by_severity, "kev_findings": p.impact.kev_findings,
                "contained_critical_share": round(p.impact.critical_share, 4), "why": list(priority_reasons(r.score)),
                "disposition": entry.to_dict() if entry else None,
            })
        return {"items": items, "as_of": self.as_of.isoformat()}

    # --- detail ---

    def case_file(self, case_id: str, max_hosts: int = 25, max_vulns: int = 15, max_events: int = 40) -> dict:
        max_hosts, max_vulns = _int(max_hosts, "max_hosts", 1, MAX_LIST), _int(max_vulns, "max_vulns", 1, MAX_VULNS)
        max_events = _int(max_events, "max_events", 1, MAX_LIST)
        data = self._case_view(case_id).to_dict()
        for key, keep in (("hosts", slice(0, max_hosts)), ("vulnerabilities", slice(0, max_vulns)),
                          ("timeline", slice(-max_events, None)), ("evidence_ids", slice(0, 25)),
                          ("fixes", slice(0, 10))):
            data[f"{key}_total"] = len(data[key])
            data[key] = data[key][keep]
        for vuln in data["vulnerabilities"]:
            vuln["solution"] = _shorten(vuln["solution"], MAX_SOLUTION_CHARS)
        entry = self._latest().get(case_id)
        data["disposition"] = entry.to_dict() if entry else None
        return data

    def fix_package(self, package_id: str, max_hosts: int = 25, max_actions: int = 15) -> dict:
        max_hosts, max_actions = _int(max_hosts, "max_hosts", 1, MAX_LIST), _int(max_actions, "max_actions", 1, MAX_LIST)
        data = self._package_view(package_id).to_dict(max_hosts)
        data["actions_total"] = len(data["package"]["actions"])
        data["package"]["actions"] = data["package"]["actions"][:max_actions]
        data["evidence_ids_total"] = len(data["evidence_ids"])
        data["evidence_ids"] = data["evidence_ids"][:25]
        data["cases_total"] = len(data["cases"])
        data["cases"] = data["cases"][:10]
        data["scope_note"] = SCOPE_NOTE
        entry = self._latest().get(package_id)
        data["disposition"] = entry.to_dict() if entry else None
        return data

    def findings(self, item_id: str, limit: int = 25, offset: int = 0) -> dict:
        """The real finding records behind a case or package, so a narrative can cite genuine ids."""
        limit, offset = _int(limit, "limit", 1, MAX_PAGE), _int(offset, "offset", 0, 10_000_000)
        _, item = self._item(item_id)
        members = sorted(item.active, key=lambda r: r.finding_id)
        return {
            "item_id": item_id, "total": len(members), "offset": offset,
            "findings": [
                {"finding_id": r.finding_id, "plugin_id": r.plugin_id, "plugin_name": r.plugin_name,
                 "severity": r.severity, "state": r.state, "hostname": r.hostname, "ipv4": r.ipv4,
                 "asset_uuid": r.asset_uuid, "port": r.port, "protocol": r.protocol,
                 "first_found": r.first_found.isoformat(), "last_found": r.last_found.isoformat(),
                 "scan_uuid": r.scan_uuid}
                for r in members[offset:offset + limit]
            ],
        }

    # --- export and disposition ---

    def export(self, item_id: str, format: str = "markdown", write: bool = False, confirm: bool = False) -> dict:
        kind, _ = self._item(item_id)
        renderers: dict[str, Callable[[], str]]
        if kind == "case":
            cf = self._case_view(item_id)
            renderers = {"markdown": lambda: case_markdown(cf), "json": lambda: case_json(cf),
                         "hosts_csv": lambda: case_hosts_csv(cf)}
        else:
            view = self._package_view(item_id)
            renderers = {"markdown": lambda: package_markdown(view), "json": lambda: package_json(view),
                         "hosts_csv": lambda: package_hosts_csv(view), "actions_csv": lambda: package_actions_csv(view)}
        if format not in renderers:
            raise ServiceError(f"format must be one of {', '.join(sorted(renderers))} for a {kind.replace('_', ' ')}")
        if write:
            if confirm is not True:
                raise ServiceError(
                    "writing export files requires confirm=true: ask the analyst first (this server cannot verify approval)")
            try:
                paths = (write_case_export(cf, self.exports_dir, True) if kind == "case"
                         else write_package_export(view, self.exports_dir, True))
            except ExportError as exc:
                raise ServiceError(str(exc)) from None
            return {"item_id": item_id, "written": [p.name for p in paths],
                    "directory": "the configured export directory (EXPOSURE_CASE_EXPORTS)"}
        if format == "json":
            raise ServiceError("json exports are large; use write=true with confirm=true, or case_file / fix_package")
        content = renderers[format]()
        if len(content) > MAX_INLINE_CHARS:
            return {"item_id": item_id, "format": format, "content": content[:MAX_INLINE_CHARS], "truncated": True,
                    "total_chars": len(content),
                    "note": "truncated for size; use write=true with confirm=true to save the complete files"}
        return {"item_id": item_id, "format": format, "content": content, "truncated": False}

    def record_disposition(self, item_id: str, analyst: str, disposition: str, note: str, confirm: bool = False) -> dict:
        kind, _ = self._item(item_id)
        try:
            entry = dlog.record_disposition(
                self.dispositions_path, item_id=item_id, kind=kind, analyst=analyst, disposition=disposition,
                note=note, confirm=confirm, data_as_of=self.as_of)
        except dlog.DispositionError as exc:
            raise ServiceError(str(exc)) from None
        return entry.to_dict()
