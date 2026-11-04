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
import logging
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
MAX_ATTEMPTS = 5  # per request; throttling (429) and temporary unavailability (502/503/504) only
MAX_RETRY_WAIT_S = 60  # cap on any wait, including a server-sent Retry-After
RETRY_BASE_WAIT_S = 2
RETRYABLE = frozenset({429, 502, 503, 504})
POLL_INTERVAL_S = 5
MAX_POLLS = 360  # 30 minutes at 5 s
PLUGIN_PATH = "/workbenches/vulnerabilities?date_range=90"
EXPORT_STATES = ["open", "reopened", "fixed"]
MAX_RESPONSE_BYTES = 128 * 1024 * 1024  # largest real export chunk is about 36 MB; matches the ingest limit
MAX_CHUNKS = 1000
_EXPORT_UUID = re.compile(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
log = logging.getLogger("fetch_tenable")


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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: urllib would copy the X-ApiKeys header to wherever it points."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


_OPEN_WITHOUT_REDIRECTS = urllib.request.build_opener(_NoRedirect).open


class TenableClient:
    """Holds the API keys privately: no __dict__, and a fixed repr that never shows them."""

    __slots__ = ("_auth", "_opener", "_sleep", "_user_agent")

    def __init__(
        self,
        access_key: str,
        secret_key: str,
        opener: Callable[..., Any] = _OPEN_WITHOUT_REDIRECTS,
        agent: str | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self._auth = f"accessKey={access_key};secretKey={secret_key}"
        self._opener = opener
        self._sleep = sleep
        self._user_agent = agent or user_agent()

    def __repr__(self) -> str:
        return "TenableClient(<credentials hidden>)"

    def _headers(self) -> dict[str, str]:
        return {
            "X-ApiKeys": self._auth,
            "User-Agent": self._user_agent,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def request(self, method: str, path: str, body: dict | None = None) -> Any:
        """One API call, retried with backoff on throttling or temporary unavailability (bounded)."""
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                return self._request_once(method, path, body)
            except urllib.error.HTTPError as exc:
                if attempt == MAX_ATTEMPTS or not _retryable(method, exc.code):
                    raise FetchError(f"{method} {path} failed: HTTP {exc.code}") from None
                wait = _retry_wait(exc, attempt)
                log.info("%s %s: HTTP %s, retrying in %ss", method, path, exc.code, wait)
                self._sleep(wait)
        raise FetchError(f"{method} {path} failed after {MAX_ATTEMPTS} attempts")  # unreachable; for type checkers

    def _request_once(self, method: str, path: str, body: dict | None) -> Any:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(BASE_URL + path, data=data, headers=self._headers(), method=method)
        try:
            with self._opener(req, timeout=REQUEST_TIMEOUT_S) as resp:
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise FetchError(f"{method} {path} response too large (limit {MAX_RESPONSE_BYTES} bytes)")
            return json.loads(raw)
        except (FetchError, urllib.error.HTTPError):
            raise  # HTTPError is handled (and maybe retried) by request()
        except urllib.error.URLError as exc:
            raise FetchError(f"{method} {path} failed: {exc.reason}") from None
        except json.JSONDecodeError:
            raise FetchError(f"{method} {path} returned invalid JSON") from None
        except (OSError, http.client.HTTPException, ValueError, RecursionError) as exc:
            raise FetchError(f"{method} {path} failed: {type(exc).__name__}") from None


def _retryable(method: str, code: int) -> bool:
    """Throttling is always safe to retry; a 5xx on the job-creating POST might have created the job already."""
    return code == 429 if method == "POST" else code in RETRYABLE


def _retry_wait(exc: urllib.error.HTTPError, attempt: int) -> float:
    """Seconds to wait: the server's Retry-After when it is a sane number of seconds, else exponential; capped."""
    header = exc.headers.get("Retry-After") if exc.headers is not None else None
    value = header.strip() if isinstance(header, str) else ""
    if value.isascii() and value.isdigit() and len(value) <= 6:  # "²" passes isdigit() but not int()
        return float(min(int(value), MAX_RETRY_WAIT_S))
    return float(min(RETRY_BASE_WAIT_S**attempt, MAX_RETRY_WAIT_S))


def _remove_quietly(path: Path) -> None:
    """Best-effort delete for cleanup; never let it mask the error being handled (Linux raises ENOTDIR)."""
    try:
        path.unlink(missing_ok=True)
    except OSError:
        log.debug("could not remove %s during cleanup", path.name, exc_info=True)


def _write_json(path: Path, data: Any) -> None:
    """Write via a temp file and ``os.replace`` so a failure never leaves a half-written file."""
    tmp = path.with_name(f".{path.name}.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)  # raw data holds hostnames and IPs
        tmp.unlink(missing_ok=True)
        with open(tmp, "x", encoding="utf-8") as handle:
            json.dump(data, handle)
        os.replace(tmp, path)
    except OSError as exc:
        raise FetchError(f"cannot write {path.name}: {type(exc).__name__}") from None
    finally:
        _remove_quietly(tmp)


def _validated_chunk_ids(status: dict) -> list[int]:
    """Chunk IDs come from the server and become URL and file names: positive ints only."""
    lists = [status.get(key) or [] for key in ("chunks_failed", "chunks_cancelled")]
    if any(not isinstance(value, list) for value in lists):
        raise FetchError("export status has an invalid failed or cancelled chunk list")
    failed = lists[0] + lists[1]
    if failed:
        raise FetchError(f"export has failed or cancelled chunks: {failed}")
    chunks = status.get("chunks_available")
    if not isinstance(chunks, list):
        raise FetchError("export status has an invalid chunk list")
    if not chunks:
        raise FetchError("export finished with no chunks")
    if len(chunks) > MAX_CHUNKS:
        raise FetchError(f"export lists too many chunks ({len(chunks)}; limit {MAX_CHUNKS})")
    if any(isinstance(c, bool) or not isinstance(c, int) or c < 1 for c in chunks):
        raise FetchError("export status has an invalid chunk id")
    return chunks


def _poll_until_finished(
    client: TenableClient, export_uuid: str, sleep: Callable[[float], None], max_polls: int
) -> dict:
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
    if out_dir.is_symlink():
        raise FetchError("output directory is a symlink; choose a real directory")
    if out_dir.exists() and any(out_dir.iterdir()):
        raise FetchError(f"output directory is not empty: {out_dir}")
    created = not out_dir.exists()
    try:
        job = client.request("POST", "/vulns/export", {"num_assets": chunk_assets, "filters": {"state": EXPORT_STATES}})
        export_uuid = job.get("export_uuid") if isinstance(job, dict) else None
        if not isinstance(export_uuid, str) or not _EXPORT_UUID.fullmatch(export_uuid):
            raise FetchError("export job did not return a valid export_uuid")
        chunk_ids = _validated_chunk_ids(_poll_until_finished(client, export_uuid, sleep, max_polls))
        for chunk_id in chunk_ids:
            chunk = client.request("GET", f"/vulns/export/{export_uuid}/chunks/{chunk_id}")
            _write_json(out_dir / "chunks" / f"chunk_{chunk_id}.json", chunk)
        _write_json(out_dir / "plugins.json", client.request("GET", PLUGIN_PATH))
    except BaseException:
        shutil.rmtree(out_dir / "chunks", ignore_errors=True)
        _remove_quietly(out_dir / "plugins.json")
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
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    log.handlers[:] = [handler]
    log.setLevel(logging.INFO)
    log.propagate = False
    try:
        access, secret = keys_from_env()
        out = fetch(TenableClient(access, secret), args.out, args.chunk_assets)
    except (FetchError, OSError) as exc:
        log.error("error: %s", exc)
        return 1
    log.info("saved export to %s", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
