#!/usr/bin/env python3
"""Fetch the pinned DVR source snapshot without vendoring it in the repo."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "benchmark" / ".out" / "dvr-source"
COMMIT = "d32d09972aec7830f5f1d4a5d274cac7aae7eb82"


def run(argv: list[str]) -> None:
    completed = subprocess.run(argv, cwd=str(ROOT), text=True,
                               capture_output=True)
    if completed.returncode != 0:
        sys.stderr.write(completed.stderr[-2000:])
        raise SystemExit(completed.returncode)


def main() -> int:
    SOURCE.parent.mkdir(parents=True, exist_ok=True)
    if not (SOURCE / ".git").is_dir():
        run(["git", "clone", "https://github.com/theowni/"
             "Damn-Vulnerable-RESTaurant-API-Game.git", str(SOURCE)])
    run(["git", "-C", str(SOURCE), "fetch", "--all", "--tags"])
    run(["git", "-C", str(SOURCE), "checkout", "--detach", COMMIT])
    actual = subprocess.check_output(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                                     text=True).strip()
    if actual != COMMIT:
        raise SystemExit(f"DVR checkout mismatch: {actual} != {COMMIT}")
    print(f"[+] DVR source {COMMIT} at {SOURCE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
