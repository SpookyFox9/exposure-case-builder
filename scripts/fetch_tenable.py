"""Fetch a Tenable Vulnerability Management export to disk.

This is the project's one outbound network path. It reads from Tenable, creating an
export job on Tenable's side, and writes under ``data/raw/`` (gitignored). The engine
reads the saved files and never calls the network.

Keys come from the environment only (never argv, never printed):
    TENABLE_ACCESS_KEY, TENABLE_SECRET_KEY

Usage:
    python scripts/fetch_tenable.py [--out data/raw/<timestamp>] [--chunk-assets 50]
"""

from __future__ import annotations

import argparse
import http.client
import importlib.metadata
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_URL = "https://cloud.tenable.com"
REQUEST_TIMEOUT_S = 120
POLL_INTERVAL_S = 5
MAX_POLLS = 360  # 30 minutes at 5 s
PLUGIN_PATH = "/workbenches/vulnerabilities?date_range=90"
EXPORT_STATES = ["open", "reopened", "fixed"]


class FetchError(RuntimeError):
    """A fetch failed; messages never contain credentials."""


def keys_from_env() -> tuple[str, str]:
    values = []
    for name in ("TENABLE_ACCESS_KEY", "TENABLE_SECRET_KEY"):
        value = (os.environ.get(name) or "").strip()
        if not value:
            raise FetchError(f"{name} is not set; load it from the vault first")
        if ";" in value or any(ch.isspace() for ch in value):
            raise FetchError(f"{name} contains characters that are invalid in a key")
        values.append(value)
    return values[0], values[1]


DEFAULT_VENDOR = "Exposure Case Builder open source"
DEFAULT_PRODUCT = "ExposureCaseBuilder"
_UNSAFE_UA_TEXT = re.compile(r"[;()\x00-\x1f\x7f]")
_UNSAFE_UA_BUILD = re.compile(r"[^0-9A-Za-z.+-]")


def _ua_text(value: str | None, default: str, limit: int = 60) -> str:
    """One User-Agent attribute: no ';', parentheses or control characters, bounded, never empty."""
    cleaned = " ".join(_UNSAFE_UA_TEXT.sub(" ", value or "").split())[:limit].strip()
    return cleaned or default


def _package_version() -> str:
    try:
        return importlib.metadata.version("exposure-case-builder")
    except importlib.metadata.PackageNotFoundError:
        return "0.1.0"


def user_agent(vendor: str | None = None, product: str | None = None, build: str | None = None) -> str:
    """Tenable's standard integration header: ``Integration/1.0 (VENDOR; PRODUCT; Build/VERSION)``.

    See https://developer.tenable.com/docs/user-agent-header. Set ``TENABLE_UA_VENDOR`` to your own company or
    team name so Tenable can tell whose integration this is; it defaults to the project name.
    """
    vendor_text = _ua_text(vendor if vendor is not None else os.environ.get("TENABLE_UA_VENDOR"), DEFAULT_VENDOR)
    product_text = _ua_text(product, DEFAULT_PRODUCT)
    build_text = _UNSAFE_UA_BUILD.sub("", build if build is not None else _package_version())[:30] or "0"
    return f"Integration/1.0 ({vendor_text}; {product_text}; Build/{build_text})"


class TenableClient:
    """Holds the API keys privately: no __dict__, and a fixed repr that never shows them."""

    __slots__ = ("_auth", "_opener", "_user_agent")

    def __init__(self, access_key: str, secret_key: str, opener: Callable[..., Any] = urllib.request.urlopen,
                 agent: str | None = None):
        self._auth = f"accessKey={access_key};secretKey={secret_key}"
        self._opener = opener
        self._user_agent = agent or user_agent()

    def __repr__(self) -> str:
        return "TenableClient(<credentials hidden>)"

    def _headers(self) -> dict[str, str]:
        return {"X-ApiKeys": self._auth, "User-Agent": self._user_agent, "Accept": "application/json",
                "Content-Type": "application/json"}

    def request(self, method: str, path: str, body: dict | None = None) -> Any:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(BASE_URL + path, data=data, headers=self._headers(), method=method)
        try:
            with self._opener(req, timeout=REQUEST_TIMEOUT_S) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            raise FetchError(f"{method} {path} failed: HTTP {exc.code}") from None
        except urllib.error.URLError as exc:
            raise FetchError(f"{method} {path} failed: {exc.reason}") from None
        except json.JSONDecodeError:
            raise FetchError(f"{method} {path} returned invalid JSON") from None
        except (OSError, http.client.HTTPException, ValueError, RecursionError) as exc:
            raise FetchError(f"{method} {path} failed: {type(exc).__name__}") from None


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _validated_chunk_ids(status: dict) -> list[int]:
    """Chunk IDs come from the server and become URL and file names: positive ints only."""
    failed = list(status.get("chunks_failed") or []) + list(status.get("chunks_cancelled") or [])
    if failed:
        raise FetchError(f"export has failed or cancelled chunks: {failed}")
    chunks = status.get("chunks_available")
    if not isinstance(chunks, list):
        raise FetchError("export status has an invalid chunk list")
    if not chunks:
        raise FetchError("export finished with no chunks")
    if any(isinstance(c, bool) or not isinstance(c, int) or c < 1 for c in chunks):
        raise FetchError("export status has an invalid chunk id")
    return chunks


def _poll_until_finished(client: TenableClient, export_uuid: str, sleep: Callable[[float], None], max_polls: int) -> dict:
    for _ in range(max_polls):
        status = client.request("GET", f"/vulns/export/{export_uuid}/status")
        if not isinstance(status, dict):
            raise FetchError("export status response was not an object")
        state = status.get("status")
        if state == "FINISHED":
            return status
        if state in ("ERROR", "CANCELLED"):
            raise FetchError(f"export ended with status {state}")
        sleep(POLL_INTERVAL_S)
    raise FetchError(f"export timed out after {max_polls} polls")


def fetch(
    client: TenableClient,
    out_dir: Path,
    chunk_assets: int = 50,
    sleep: Callable[[float], None] = time.sleep,
    max_polls: int = MAX_POLLS,
) -> Path:
    """Run one export job and save chunks plus plugin-level context under ``out_dir``.

    On any failure the files this call wrote are removed so a retry can reuse the path.
    """
    out_dir = Path(out_dir)
    if out_dir.exists() and any(out_dir.iterdir()):
        raise FetchError(f"output directory is not empty: {out_dir}")
    created = not out_dir.exists()
    try:
        job = client.request("POST", "/vulns/export", {"num_assets": chunk_assets, "filters": {"state": EXPORT_STATES}})
        export_uuid = job.get("export_uuid") if isinstance(job, dict) else None
        if not isinstance(export_uuid, str) or not export_uuid.strip():
            raise FetchError("export job did not return an export_uuid")
        chunk_ids = _validated_chunk_ids(_poll_until_finished(client, export_uuid, sleep, max_polls))
        for chunk_id in chunk_ids:
            chunk = client.request("GET", f"/vulns/export/{export_uuid}/chunks/{chunk_id}")
            _write_json(out_dir / "chunks" / f"chunk_{chunk_id}.json", chunk)
        _write_json(out_dir / "plugins.json", client.request("GET", PLUGIN_PATH))
    except BaseException:
        shutil.rmtree(out_dir / "chunks", ignore_errors=True)
        (out_dir / "plugins.json").unlink(missing_ok=True)
        if created:
            shutil.rmtree(out_dir, ignore_errors=True)
        raise
    return out_dir


def _positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    parser.add_argument("--out", type=Path, default=Path("data/raw") / stamp)
    parser.add_argument("--chunk-assets", type=_positive_int, default=50, help="assets per export chunk")
    args = parser.parse_args(argv)
    try:
        access, secret = keys_from_env()
        out = fetch(TenableClient(access, secret), args.out, args.chunk_assets)
    except (FetchError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"saved export to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
