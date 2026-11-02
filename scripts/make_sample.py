"""Build the small committed sample (data/sample/) from a full saved export.

Deterministic and cluster-oriented: keeps every non-info finding for the top plugins by
number of affected assets, plus a few notable plugins (exploited by malware or with a
reopened finding), across all assets. Strips fields the engine never reads and truncates
plugin output. The competition tenant data is fake and masked; the full export stays
gitignored under data/raw/.

Usage:
    python scripts/make_sample.py data/raw/<export> data/sample [--plugins 40] [--notable 10]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from exposure_case.ingest import IngestError, iter_raw_records, parse_record, read_json_file

ASSET_KEYS = ("uuid", "hostname", "ipv4", "device_type", "operating_system")
PLUGIN_KEYS = (
    "id", "name", "family", "synopsis", "exploit_available", "exploited_by_malware", "in_the_news",
    "has_patch", "unsupported_by_vendor", "checks_for_default_account",
)
PORT_KEYS = ("port", "protocol", "service")
SCAN_KEYS = ("uuid", "started_at")
TOP_KEYS = ("finding_id", "state", "severity", "first_found", "last_found")


def _pick(obj: Any, keys: tuple[str, ...]) -> dict:
    return {k: obj[k] for k in keys if isinstance(obj, dict) and k in obj}


def _trim(record: dict, output_chars: int) -> dict:
    out = _pick(record, TOP_KEYS)
    out["output"] = str(record.get("output") or "")[:output_chars]
    out["asset"] = _pick(record.get("asset"), ASSET_KEYS)
    out["plugin"] = _pick(record.get("plugin"), PLUGIN_KEYS)
    out["port"] = _pick(record.get("port"), PORT_KEYS)
    out["scan"] = _pick(record.get("scan"), SCAN_KEYS)
    return out


def _load_records(src: Path) -> list[dict]:
    """Raw records in numeric chunk order; each is validated with the engine's own parser."""
    records: list[dict] = []
    for name, index, raw in iter_raw_records(src):
        try:
            parse_record(raw)
        except IngestError as exc:
            raise IngestError(f"{name}[{index}]: {exc}") from exc
        records.append(raw)
    return records


def _select_plugins(records: list[dict], n_plugins: int, n_notable: int) -> set[int]:
    assets: dict[int, set[str]] = {}
    notable: set[int] = set()
    for r in records:
        pid = r["plugin"]["id"]
        if r.get("state") != "FIXED":
            assets.setdefault(pid, set()).add(r["asset"]["uuid"])
        if r.get("state") == "REOPENED" or r["plugin"].get("exploited_by_malware"):
            notable.add(pid)
    ranked = sorted(assets, key=lambda pid: (-len(assets[pid]), pid))
    top = ranked[:n_plugins]
    extra = [pid for pid in ranked if pid in notable and pid not in top][:n_notable]
    return set(top) | set(extra)


def build_sample(src: Path, out: Path, n_plugins: int = 40, n_notable: int = 10, output_chars: int = 200) -> Path:
    src, out = Path(src), Path(out)
    if out.exists() and any(out.iterdir()):
        raise ValueError(f"output directory is not empty: {out}")
    if n_plugins < 1 or n_notable < 0:
        raise ValueError("n_plugins must be >= 1 and n_notable >= 0")
    records = [r for r in _load_records(src) if r.get("severity") != "info"]
    if not records:
        raise ValueError("no non-info findings in the source export")
    keep = _select_plugins(records, n_plugins, n_notable)

    kept = [_trim(r, output_chars) for r in records if r["plugin"]["id"] in keep]
    plugins_path = src / "plugins.json"
    rows: list = []
    if plugins_path.is_file():
        data = read_json_file(plugins_path)
        found = data.get("vulnerabilities") if isinstance(data, dict) else None
        if not isinstance(found, list):
            raise IngestError("plugins.json must contain a 'vulnerabilities' list")
        rows = found

    (out / "chunks").mkdir(parents=True, exist_ok=True)
    (out / "chunks" / "chunk_1.json").write_text(json.dumps(kept, indent=0, sort_keys=True), encoding="utf-8")
    (out / "plugins.json").write_text(
        json.dumps({"vulnerabilities": [r for r in rows if isinstance(r, dict) and r.get("plugin_id") in keep]}, indent=0, sort_keys=True),
        encoding="utf-8",
    )
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("src", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--plugins", type=int, default=40, help="top plugins by affected-asset count")
    parser.add_argument("--notable", type=int, default=10, help="extra malware-exploited or reopened plugins")
    args = parser.parse_args(argv)
    try:
        out = build_sample(args.src, args.out, args.plugins, args.notable)
    except (ValueError, OSError) as exc:  # IngestError is a ValueError
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"wrote sample to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
