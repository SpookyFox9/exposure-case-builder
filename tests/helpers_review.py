"""Shared helpers for tests that use the committed sample (importable because tests/ is on sys.path)."""

import shutil
from pathlib import Path

from exposure_case.service import Workspace

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample"


def ws_for(tmp_path: Path) -> Workspace:
    return Workspace.load(SAMPLE, exports_dir=tmp_path / "exports", dispositions_path=tmp_path / "d.jsonl")


def copy_sample(dest: Path) -> Path:
    shutil.copytree(SAMPLE, dest)
    return dest
