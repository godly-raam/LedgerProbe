#!/usr/bin/env python3
"""Measure race detection on the loopback wallet fixtures.

N=50 fresh runs per fixture/mode, each run sending 10 requests across 5 rounds.
The wide fixture has a 30 ms check/write gap; the yield-only fixture has only
``await asyncio.sleep(0)`` between the check and the write. The latter is
timing-dependent and deliberately excluded from pytest and the corpus gate.
"""
from __future__ import annotations

import argparse
import asyncio
import copy
import importlib.util
import json
import math
import os
import socket
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import yaml

from pkg.guardrails import GuardedClient
from pkg.parser import load_inventory
from pkg.rules import load_rules, run_rules

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "race_server"
RULE_FILE = FIXTURES / "rules_race_wallet.yaml"
DOCS = ROOT / "docs" / "RACE.md"
RUNS = 50
FIXTURES_TO_STUDY = (
    ("wallet_race_vulnerable", "wide (30 ms gap)"),
    ("wallet_race_vulnerable_narrow_yield", "narrow (yield-only)"),
)
MODES = ("burst", "last_byte")
MARKER_START = "<!-- race-study:start -->"
MARKER_END = "<!-- race-study:end -->"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _start(profile: str) -> tuple[subprocess.Popen[bytes], int]:
    port = _free_port()
    env = {**os.environ, "RACE_PROFILE": profile}
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "tests.fixtures.race_server.app:app",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            if httpx.get(f"http://127.0.0.1:{port}/race/health", timeout=0.2).status_code == 200:
                return process, port
        except Exception:
            pass
        if process.poll() is not None:
            break
        time.sleep(0.03)
    stderr = process.stderr.read().decode("utf-8", "replace") if process.stderr else ""
    process.kill()
    raise RuntimeError(f"race fixture {profile} did not start: {stderr[-1000:]}")


async def _one_mode(port: int, profile: str, mode: str, runs: int) -> dict:
    base = load_rules([str(RULE_FILE)])[0]
    base["race"]["sync"] = mode
    base["race"]["requests"] = 10
    base["race"]["rounds"] = 5
    fails = 0
    spreads: list[float] = []
    first_hit_rounds: list[int] = []
    actual_modes: dict[str, int] = {}
    async with GuardedClient(max_rps=10000, timeout=5) as client:
        inventory = await load_inventory(str(FIXTURES / "openapi.json"), client)
        inventory["base_url"] = f"http://127.0.0.1:{port}"
        for _ in range(runs):
            rule = copy.deepcopy(base)
            result = (await run_rules(
                inventory, [rule], client,
                contexts={
                    "owner": {"X-Actor": "owner"},
                    "other": {"X-Actor": "other"},
                },
                variables={}, allow_mutations=True,
            ))[0]
            evidence = result.get("evidence", {})
            if evidence.get("median_spread_ms") is not None:
                spreads.append(float(evidence["median_spread_ms"]))
            actual = evidence.get("sync_mode", mode)
            actual_modes[actual] = actual_modes.get(actual, 0) + 1
            if (result.get("verdict") == "FAIL"
                    and result.get("reason") == "race_invariant_violated"):
                fails += 1
                first_hit_rounds.append(evidence.get("first_violation_round"))
    return {
        "profile": profile,
        "mode": mode,
        "runs": runs,
        "fails": fails,
        "median_spread_ms": statistics.median(spreads) if spreads else None,
        "first_hit_rounds": first_hit_rounds,
        "actual_sync_modes": actual_modes,
    }


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion."""
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denominator = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return max(0.0, centre - margin), min(1.0, centre + margin)


def _row(row: dict, label: str) -> str:
    low, high = wilson(row["fails"], row["runs"])
    rate = 100 * row["fails"] / row["runs"]
    spread = (f"{row['median_spread_ms']:.6f}"
              if row["median_spread_ms"] is not None else "n/a")
    return (f"| `{row['profile']}` ({label}) | `{row['mode']}` | {row['runs']} | "
            f"{row['fails']} | {rate:.1f}% | {100 * low:.1f}%–{100 * high:.1f}% | "
            f"{spread} |")


def _study_markdown(rows: list[dict]) -> str:
    labels = dict(FIXTURES_TO_STUDY)
    table = [
        MARKER_START,
        "## Detection study",
        "",
        f"N={RUNS} fresh runs per fixture/mode. Each run used 10 requests and 5 rounds.",
        "The wide fixture (`wallet_race_vulnerable`) has a 30 ms check/write gap.",
        "The narrow fixture (`wallet_race_vulnerable_narrow_yield`) has only",
        "`await asyncio.sleep(0)` between the check and the write; it is",
        "timing-dependent and is excluded from pytest and the corpus gate. CI uses",
        "`wallet_race_vulnerable_narrow_deterministic` instead.",
        "",
        "| Fixture | Mode | Runs | FAIL count | FAIL rate | Wilson 95% CI | Median release spread (ms) |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    table.extend(_row(row, labels.get(row["profile"], "fixture")) for row in rows)
    below = [row for row in rows if row["fails"] < row["runs"]
             and row["mode"] == "last_byte"]
    table += [
        "",
        "The interval is a Wilson score interval for the observed FAIL count.",
        "Median release spread is the median of each run's evidence field; it is",
        "not a detection-rate estimate.",
        "",
        *(f"`last_byte` on `{row['profile']}` detected {row['fails']}/{row['runs']} "
          f"({100 * row['fails'] / row['runs']:.1f}%), below 100%."
          for row in below),
        "",
        "| Mode | Status |",
        "| --- | --- |",
        "| `h2_single_packet` | **not tested** — optional `h2` package is not installed; no h2 measurement was performed. |",
        "",
        MARKER_END,
    ]
    return "\n".join(table)


def _update_docs(rows: list[dict]) -> None:
    text = DOCS.read_text(encoding="utf-8")
    study = _study_markdown(rows)
    if MARKER_START in text and MARKER_END in text:
        before, _, rest = text.partition(MARKER_START)
        _, _, after = rest.partition(MARKER_END)
        new_text = before + study + after
    else:
        before, separator, rest = text.partition("## Detection study")
        if not separator:
            raise RuntimeError("docs/RACE.md has no Detection study section")
        _, _, after = rest.partition("## Safe use")
        new_text = before + study + "\n\n## Safe use" + after
    DOCS.write_text(new_text.rstrip() + "\n", encoding="utf-8")


def _h2_available() -> bool:
    return importlib.util.find_spec("h2") is not None


async def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=RUNS)
    parser.add_argument("--no-write", action="store_true")
    args = parser.parse_args(argv)
    if args.runs < 1:
        parser.error("--runs must be >= 1")

    rows: list[dict] = []
    for profile, _ in FIXTURES_TO_STUDY:
        process, port = _start(profile)
        try:
            for mode in MODES:
                rows.append(await _one_mode(port, profile, mode, args.runs))
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "runs": args.runs,
        "requests_per_run": 10,
        "rounds_per_run": 5,
        "h2_available": _h2_available(),
        "rows": rows,
    }
    print(json.dumps(payload, indent=2))
    print()
    print("| Fixture | Mode | Runs | FAIL count | FAIL rate | Wilson 95% CI | Median release spread (ms) |")
    print("| --- | --- | ---: | ---: | ---: | ---: | ---: |")
    for row in rows:
        print(_row(row, dict(FIXTURES_TO_STUDY)[row["profile"]]))
    print()
    print("h2_single_packet: not tested (h2 unavailable)")
    if not args.no_write:
        _update_docs(rows)
        print(f"updated {DOCS.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
