"""Read a saved Tenable vulnerability export from disk. No network access.

Layout of an export directory (written by ``scripts/fetch_tenable.py``)::

    <dir>/chunks/chunk_<n>.json   JSON list of per-finding export records
    <dir>/plugins.json            optional /workbenches/vulnerabilities response
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .schema import Evidence

VALID_STATES = frozenset({"OPEN", "REOPENED", "FIXED"})
MAX_FILE_BYTES = 256 * 1024 * 1024  # largest export chunk seen is about 36 MB

_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$")


class IngestError(ValueError):
    """Raised when export data is missing, malformed or inconsistent."""


@dataclass(frozen=True)
class FindingRecord:
    """One normalized per-finding record from the export."""

    finding_id: str
    plugin_id: int
    plugin_name: str
    plugin_family: str
    synopsis: str
    severity: str
    state: str
    first_found: datetime
    last_found: datetime
    asset_uuid: str
    hostname: str
    ipv4: str
    operating_system: tuple[str, ...]
    device_type: str
    port: int | None
    protocol: str
    service: str
    scan_uuid: str
    scan_started: datetime | None
    exploit_available: bool
    exploited_by_malware: bool
    in_the_news: bool
    has_patch: bool
    unsupported_by_vendor: bool
    checks_for_default_account: bool
    output: str
    # Fix and risk context carried by the export (all optional; empty fields are omitted by Tenable).
    solution: str = ""
    see_also: tuple[str, ...] = ()
    cves: tuple[str, ...] = ()
    cpe: tuple[str, ...] = ()
    has_workaround: bool = False
    patch_published: datetime | None = None
    cvss3_base_score: float | None = None
    epss_score: float | None = None
    vpr_score: float | None = None
    vpr_severity: str = ""
    on_cisa_kev: bool = False
    exploit_code_maturity: str = ""
    # Finding-level fix history (present on a minority of findings; seconds for fix_seconds).
    last_fixed: datetime | None = None
    resurfaced: datetime | None = None
    fix_seconds: int | None = None

    def evidence(self) -> Evidence:
        return Evidence(source="finding", record_id=self.finding_id)


@dataclass(frozen=True)
class PluginInfo:
    """Plugin-level context from the workbench endpoint (all scores optional)."""

    plugin_id: int
    count: int
    vpr_score: float | None
    cvss_base_score: float | None
    cvss3_base_score: float | None


def _parse_ts(value: Any, field: str) -> datetime:
    """Parse ISO-8601 with any fraction length (Python 3.10's fromisoformat is strict)."""
    if not isinstance(value, str) or not value.strip():
        raise IngestError(f"missing or non-string timestamp: {field}")
    match = _TS_RE.match(value.strip())
    if not match:
        raise IngestError(f"bad timestamp in {field}: {value!r}")
    base, fraction, zone = match.groups()
    if zone in (None, "Z"):
        zone = "+00:00"
    elif ":" not in zone:
        zone = f"{zone[:3]}:{zone[3:]}"
    text = f"{base}.{(fraction or '0')[:6].ljust(6, '0')}{zone}"
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise IngestError(f"bad timestamp in {field}: {value!r}") from exc


def _text(value: Any) -> str:
    """Strings only: other types (dicts, lists, numbers) become empty, never a repr."""
    return value if isinstance(value, str) else ""


def read_json_file(path: Path) -> Any:
    """Read one JSON file with a size cap; every failure becomes an IngestError."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise IngestError(f"cannot read {path.name}: {type(exc).__name__}") from None
    if size > MAX_FILE_BYTES:
        raise IngestError(f"{path.name} is too large (limit {MAX_FILE_BYTES} bytes)")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:  # ValueError covers JSON and UTF-8 errors
        raise IngestError(f"cannot read {path.name}: {type(exc).__name__}") from None


def _required_str(obj: dict, key: str, where: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        raise IngestError(f"missing required field: {where}.{key}")
    return value.strip()


def _optional_section(raw: dict, key: str) -> dict:
    value = raw.get(key)
    return value if isinstance(value, dict) else {}


def _section(raw: dict, key: str) -> dict:
    value = raw.get(key)
    if not isinstance(value, dict):
        raise IngestError(f"missing required section: {key}")
    return value


def _opt_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _str_tuple(value: Any) -> tuple[str, ...]:
    """A list of strings; anything else (or non-string items) is dropped."""
    return tuple(v.strip() for v in value if isinstance(v, str) and v.strip()) if isinstance(value, list) else ()


def _opt_number(value: Any, low: float | None = None, high: float | None = None) -> float | None:
    """A real number (never a bool), optionally range-checked; otherwise None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    if (low is not None and value < low) or (high is not None and value > high):
        return None
    return float(value)


def _optional_ts(value: Any) -> datetime | None:
    """Optional metadata timestamps degrade to None; required ones still raise via _parse_ts."""
    try:
        return _parse_ts(value, "optional") if value else None
    except IngestError:
        return None


def parse_record(raw: Any) -> FindingRecord:
    """Validate and normalize one export record."""
    if not isinstance(raw, dict):
        raise IngestError("record is not an object")
    asset, plugin = _section(raw, "asset"), _section(raw, "plugin")
    port = _optional_section(raw, "port")
    scan = _optional_section(raw, "scan")

    state = _required_str(raw, "state", "record").upper()
    if state not in VALID_STATES:
        raise IngestError(f"unknown state: {state!r}")
    plugin_id = _opt_int(plugin.get("id"))
    if plugin_id is None:
        raise IngestError("missing required field: plugin.id")

    started = scan.get("started_at")
    os_list = asset.get("operating_system")
    vpr = _optional_section(plugin, "vpr")
    fix_seconds = _opt_int(raw.get("time_taken_to_fix"))
    return FindingRecord(
        finding_id=_required_str(raw, "finding_id", "record"),
        plugin_id=plugin_id,
        plugin_name=_text(plugin.get("name")),
        plugin_family=_text(plugin.get("family")),
        synopsis=_text(plugin.get("synopsis")),
        severity=_required_str(raw, "severity", "record").lower(),
        state=state,
        first_found=_parse_ts(raw.get("first_found"), "first_found"),
        last_found=_parse_ts(raw.get("last_found"), "last_found"),
        asset_uuid=_required_str(asset, "uuid", "asset"),
        hostname=_text(asset.get("hostname")),
        ipv4=_text(asset.get("ipv4")),
        operating_system=tuple(o for o in os_list if isinstance(o, str)) if isinstance(os_list, list) else (),
        device_type=_text(asset.get("device_type")),
        port=_opt_int(port.get("port")),
        protocol=_text(port.get("protocol")),
        service=_text(port.get("service")),
        scan_uuid=_text(scan.get("uuid")),
        scan_started=_parse_ts(started, "scan.started_at") if started else None,
        exploit_available=bool(plugin.get("exploit_available")),
        exploited_by_malware=bool(plugin.get("exploited_by_malware")),
        in_the_news=bool(plugin.get("in_the_news")),
        has_patch=bool(plugin.get("has_patch")),
        unsupported_by_vendor=bool(plugin.get("unsupported_by_vendor")),
        checks_for_default_account=bool(plugin.get("checks_for_default_account")),
        output=_text(raw.get("output")),
        solution=_text(plugin.get("solution")).strip(),
        see_also=_str_tuple(plugin.get("see_also")),
        cves=_str_tuple(plugin.get("cve")),
        cpe=_str_tuple(plugin.get("cpe")),
        has_workaround=plugin.get("has_workaround") is True,
        patch_published=_optional_ts(plugin.get("patch_publication_date")),
        cvss3_base_score=_opt_number(plugin.get("cvss3_base_score"), 0, 10),
        epss_score=_opt_number(plugin.get("epss_score"), 0),
        vpr_score=_opt_number(vpr.get("score"), 0, 10),
        vpr_severity=_text(vpr.get("vpr_severity")),
        on_cisa_kev=vpr.get("on_cisa_kev") is True,
        exploit_code_maturity=_text(vpr.get("exploit_code_maturity")),
        last_fixed=_optional_ts(raw.get("last_fixed")),
        resurfaced=_optional_ts(raw.get("resurfaced_date")),
        fix_seconds=fix_seconds if fix_seconds is not None and fix_seconds >= 0 else None,
    )


def _chunk_order(path: Path) -> tuple[int, str]:
    match = re.search(r"(\d+)", path.stem)
    return (int(match.group(1)) if match else 0, path.name)


def iter_raw_records(root: str | Path) -> Iterator[tuple[str, int, Any]]:
    """Yield ``(chunk file name, index, raw record)`` for every chunk under ``root/chunks``."""
    chunk_dir = Path(root) / "chunks"
    if not chunk_dir.is_dir():
        raise IngestError(f"no chunks directory at {chunk_dir}")
    files = sorted(chunk_dir.glob("*.json"), key=_chunk_order)
    if not files:
        raise IngestError(f"no chunk files in {chunk_dir}")
    for path in files:
        data = read_json_file(path)
        if not isinstance(data, list):
            raise IngestError(f"{path.name} must contain a JSON list")
        for index, raw in enumerate(data):
            yield path.name, index, raw


def load_findings(root: str | Path) -> tuple[FindingRecord, ...]:
    """Load every chunk in numeric order; reject malformed records and duplicate IDs."""
    records: list[FindingRecord] = []
    seen: set[str] = set()
    for name, index, raw in iter_raw_records(root):
        try:
            record = parse_record(raw)
        except IngestError as exc:
            raise IngestError(f"{name}[{index}]: {exc}") from exc
        if record.finding_id in seen:
            raise IngestError(f"duplicate finding_id {record.finding_id!r} in {name}[{index}]")
        seen.add(record.finding_id)
        records.append(record)
    return tuple(records)


def _opt_float(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def load_plugin_info(root: str | Path) -> dict[int, PluginInfo]:
    """Load ``plugins.json`` if present; an absent file means no plugin context."""
    path = Path(root) / "plugins.json"
    if not path.is_file():
        return {}
    data = read_json_file(path)
    rows = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise IngestError("plugins.json must contain a 'vulnerabilities' list")

    info: dict[int, PluginInfo] = {}
    for row in rows:
        plugin_id = _opt_int(row.get("plugin_id")) if isinstance(row, dict) else None
        if plugin_id is None:
            continue
        info[plugin_id] = PluginInfo(
            plugin_id=plugin_id,
            count=_opt_int(row.get("count")) or 0,
            vpr_score=_opt_float(row.get("vpr_score")),
            cvss_base_score=_opt_float(row.get("cvss_base_score")),
            cvss3_base_score=_opt_float(row.get("cvss3_base_score")),
        )
    return info
