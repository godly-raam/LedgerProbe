"""Keep the dashboard benchmark data tied to the recorded benchmark tables."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "dashboard" / "data" / "benchmark.json"
RESULTS = ROOT / "benchmark" / "RESULTS.md"
README = ROOT / "README.md"


def _parts(line: str) -> list[str]:
    return [part.strip() for part in line.strip().strip("|").split("|")]


def _counts(cell: str) -> list[int]:
    return [int(value) for value in cell.split("/")]


def _dashboard_rows() -> dict[tuple[str, str], dict[str, list[int]]]:
    data = json.loads(DASHBOARD.read_text(encoding="utf-8"))
    return {
        (row["target"].lower(), row["mode"]): {"v1": row["v1"], "v2": row["v2"], "v3": row["v3"]}
        for row in data["rows"]
    }


def _readme_rows() -> dict[tuple[str, str], dict[str, list[int]]]:
    rows = {}
    for line in README.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| VAmPI |") and not line.startswith("| crAPI |"):
            continue
        parts = _parts(line)
        mode = parts[1].strip("`") if len(parts) > 1 else ""
        if len(parts) != 5 or mode not in {"legacy_strict", "legacy_lenient", "differential"}:
            continue
        rows[(parts[0].lower(), mode)] = {
            "v1": _counts(parts[2]),
            "v2": _counts(parts[3]),
            "v3": _counts(parts[4]),
        }
    return rows


def _recorded_v3_rows() -> dict[tuple[str, str], list[int]]:
    rows = {}
    for line in RESULTS.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| vampi |") and not line.startswith("| crapi |"):
            continue
        parts = _parts(line)
        if len(parts) != 13 or parts[2] != "ok":
            continue
        rows[(parts[0].lower(), parts[1])] = [int(value) for value in parts[4:10]]
    return rows


def test_dashboard_data_matches_recorded_benchmark_tables():
    dashboard = _dashboard_rows()
    readme = _readme_rows()
    recorded_v3 = _recorded_v3_rows()

    assert dashboard
    assert dashboard == readme
    assert {key: row["v3"] for key, row in dashboard.items()} == recorded_v3
