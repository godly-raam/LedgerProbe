"""Run wallet race fixtures 20 times in each real synchronization mode.

This is a local study, not a benchmark score. It uses the same loopback fixtures
and rules as the corpus. h2 is reported as untested unless the optional package
is installed and a real HTTP/2 fixture is used; this study does not install it.
"""
from __future__ import annotations

import asyncio
import copy
import importlib.util
import json
import statistics
from pathlib import Path

from pkg.guardrails import GuardedClient
from pkg.parser import load_inventory
from pkg.rules import load_rules, run_rules
from tests.test_race import _start

FIXTURES = Path(__file__).parent / "fixtures" / "race_server"
MODES = ("burst", "last_byte")
PROFILES = ("wallet_race_vulnerable", "wallet_race_vulnerable_narrow")


async def one_mode(port: int, profile: str, mode: str, runs: int = 20):
    rule = load_rules([str(FIXTURES / "rules_race_wallet.yaml")])[0]
    rule["race"]["sync"] = mode
    async with GuardedClient(max_rps=10000, timeout=5) as client:
        inventory = await load_inventory(str(FIXTURES / "openapi.json"), client)
        inventory["base_url"] = f"http://127.0.0.1:{port}"
        hits = 0
        first_hits = []
        spreads = []
        notes = {}
        for _ in range(runs):
            selected = copy.deepcopy(rule)
            result = (await run_rules(
                inventory, [selected], client,
                contexts={"owner": {"X-Actor": "owner"}, "other": {"X-Actor": "other"}},
                variables={}, allow_mutations=True,
            ))[0]
            evidence = result.get("evidence", {})
            spreads.append(evidence.get("median_spread_ms", 0.0))
            actual = evidence.get("sync_mode", mode)
            notes[actual] = notes.get(actual, 0) + 1
            if result["verdict"] == "FAIL" and result.get("reason") == "race_invariant_violated":
                hits += 1
                first_hits.append(evidence.get("first_violation_round"))
    return {
        "profile": profile,
        "mode": mode,
        "runs": runs,
        "fails": hits,
        "fail_rate": hits / runs,
        "first_hit_rounds": first_hits,
        "median_spread_ms": statistics.median(spreads) if spreads else None,
        "actual_sync_modes": notes,
    }


async def main():
    rows = []
    for profile in PROFILES:
        process, port = _start(profile)
        try:
            for mode in MODES:
                rows.append(await one_mode(port, profile, mode))
        finally:
            process.terminate()
            process.wait(timeout=3)
    h2_available = importlib.util.find_spec("h2") is not None
    print(json.dumps({"rows": rows, "h2_available": h2_available}, indent=2))
    print("\n| Fixture | Mode | FAIL runs | FAIL rate | Median spread (ms) | Rounds to first hit |")
    print("| --- | --- | ---: | ---: | ---: | --- |")
    for row in rows:
        hits = row["first_hit_rounds"]
        first = f"{min(hits)}" if hits else "none"
        spread = f"{row['median_spread_ms']:.6f}" if row["median_spread_ms"] is not None else "n/a"
        label = "wide (30 ms)" if row["profile"].endswith("vulnerable") else "narrow (yield)"
        print(f"| {label} | `{row['mode']}` | {row['fails']}/{row['runs']} | "
              f"{row['fail_rate'] * 100:.0f}% | {spread} | {first} |")
    print(f"\nh2_single_packet: {'available but not tested' if h2_available else 'not tested (h2 unavailable)'}")


if __name__ == "__main__":
    asyncio.run(main())
