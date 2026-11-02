"""CLI: write the seeded synthetic dataset."""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from insider_case.synthetic import generate  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out_dir", nargs="?", type=Path, default=ROOT / "data" / "synthetic")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)
    generate(args.out_dir, seed=args.seed)
    print(f"wrote synthetic dataset to {args.out_dir} (seed={args.seed})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
