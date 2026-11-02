"""Export cases and fix packages as Markdown, CSV and JSON, and write them to disk.

Markdown rendering lives in ``report_md`` and the text neutralizers in ``text_safety``; this module adds the
CSV and JSON forms and the file writers, and re-exports the public names so callers have one import.

Everything Tenable supplies is untrusted and is neutralized on the way out (see ``text_safety``). The JSON
export is the exact, unescaped copy; other markups (Slack, Jira) need their own escaping, so use the JSON for
those. Output is deterministic (no wall-clock time). File writes need ``confirm=True``, go only to the
directory given, and are atomic per file.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from collections.abc import Iterable
from pathlib import Path

from .case import CaseFile, PackageView
from .cluster import slugify
from .fixes import HostLine
from .report_md import case_markdown, package_markdown
from .text_safety import csv_cell, md_cell, md_code, md_text

__all__ = [
    "ExportError",
    "case_hosts_csv",
    "case_json",
    "case_markdown",
    "csv_cell",
    "md_cell",
    "md_code",
    "md_text",
    "package_actions_csv",
    "package_hosts_csv",
    "package_json",
    "package_markdown",
    "write_case_export",
    "write_package_export",
]

MAX_STEM_CHARS = 60
_HOST_HEADER = [
    "asset_uuid",
    "hostname",
    "ipv4",
    "operating_system",
    "findings",
    "plugins",
    "worst_severity",
    "oldest_first_found",
]
_ACTION_HEADER = ["solution", "plugins", "findings", "hosts", "worst_severity", "critical_findings", "critical_share"]


class ExportError(ValueError):
    """Raised when an export cannot be written."""


def _csv(header: list[str], rows: Iterable[list[object]]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(header)
    for row in rows:
        writer.writerow([csv_cell(v) for v in row])
    return out.getvalue()


def _json(data: object) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _host_csv_rows(hosts: Iterable[HostLine]) -> list[list[object]]:
    return [
        [
            h.asset_uuid,
            h.hostname,
            h.ipv4,
            h.operating_system,
            h.findings,
            h.plugins,
            h.worst_severity,
            h.oldest_first_found.isoformat(),
        ]
        for h in hosts
    ]


def package_hosts_csv(view: PackageView) -> str:
    return _csv(_HOST_HEADER, _host_csv_rows(view.package.hosts))


def package_actions_csv(view: PackageView) -> str:
    rows: list[list[object]] = [
        [a.solution, a.plugins, a.findings, a.hosts, a.worst_severity, a.critical_findings, round(a.critical_share, 4)]
        for a in view.package.actions
    ]
    return _csv(_ACTION_HEADER, rows)


def package_json(view: PackageView) -> str:
    return _json(view.to_dict())


def case_hosts_csv(cf: CaseFile) -> str:
    return _csv(_HOST_HEADER, _host_csv_rows(cf.hosts))


def case_json(cf: CaseFile) -> str:
    return _json(cf.to_dict())


# --- writing ---


def _safe_stem(identifier: str, fallback: str) -> str:
    """Readable, bounded, collision-proof file stem: slug plus a short hash of the exact id."""
    slug = slugify(identifier)[:MAX_STEM_CHARS].strip("-") or fallback
    digest = hashlib.sha1(identifier.encode("utf-8", "replace"), usedforsecurity=False).hexdigest()[:8]
    return f"{slug}-{digest}"


def _plan_files(files: dict[str, str], root: Path) -> list[tuple[Path, Path, str, str]]:
    plan = []
    for name, content in files.items():
        if not name or Path(name).name != name:
            raise ExportError(f"refusing to write outside the export directory: {name}")
        final = root / name
        if final.is_dir():
            raise ExportError(f"a directory already exists at {name}")
        plan.append((root / f".{name}.tmp", final, content, "utf-8-sig" if name.endswith(".csv") else "utf-8"))
    return plan


def _write_all(files: dict[str, str], out_dir: Path, confirm: bool) -> tuple[Path, ...]:
    """Write every file via a temp file and ``os.replace`` (which replaces a symlink rather than following it)."""
    if confirm is not True:
        raise ExportError("writing export files requires confirm=true")
    try:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        root = out_dir.resolve()
    except OSError as exc:
        raise ExportError(f"cannot use the export directory: {type(exc).__name__}") from None
    plan = _plan_files(files, root)
    try:
        for tmp, _, content, encoding in plan:
            tmp.unlink(missing_ok=True)
            with open(tmp, "x", encoding=encoding, newline="\n") as handle:
                handle.write(content)
        for tmp, final, _, _ in plan:
            os.replace(tmp, final)
    except OSError as exc:
        raise ExportError(f"export failed: {type(exc).__name__}") from None
    finally:
        for tmp, *_ in plan:
            tmp.unlink(missing_ok=True)
    return tuple(final for _, final, _, _ in plan)


def write_package_export(view: PackageView, out_dir: Path, confirm: bool = False) -> tuple[Path, ...]:
    stem = _safe_stem(view.package.package_id, "package")
    return _write_all(
        {
            f"{stem}.md": package_markdown(view),
            f"{stem}.json": package_json(view),
            f"{stem}-hosts.csv": package_hosts_csv(view),
            f"{stem}-actions.csv": package_actions_csv(view),
        },
        out_dir,
        confirm,
    )


def write_case_export(cf: CaseFile, out_dir: Path, confirm: bool = False) -> tuple[Path, ...]:
    stem = _safe_stem(cf.case_id, "case")
    return _write_all(
        {f"{stem}.md": case_markdown(cf), f"{stem}.json": case_json(cf), f"{stem}-hosts.csv": case_hosts_csv(cf)},
        out_dir,
        confirm,
    )
