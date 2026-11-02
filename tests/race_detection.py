"""Run the wallet-vulnerable fixture 20 times in each sync mode.

This is a local study, not a benchmark score. It uses the same loopback fixture
and rule as the corpus and prints a markdown table for docs/RACE.md.
"""
from __future__ import annotations

import asyncio
import copy
import json
import statistics
from pathlib import Path

from pkg.guardrails import GuardedClient
from pkg.parser import load_inventory
from pkg.rules import load_rules, run_rules
from tests.test_race import _start

FIXTURES = Path(__file__).parent / "fixtures" / "race_server"
MODES = ("burst", "last_byte", "h2_single_packet")


async def one_mode(port: int, mode: str, runs: int = 20):
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
            notes[evidence.get("sync_mode", mode)] = notes.get(evidence.get("sync_mode", mode), 0) + 1
            if result["verdict"] == "FAIL" and result.get("reason") == "race_invariant_violated":
                hits += 1
                first_hits.append(evidence.get("first_violation_round"))
    return {
        "mode": mode,
        "runs": runs,
        "fails": hits,
        "fail_rate": hits / runs,
        "first_hit_rounds": first_hits,
        "median_spread_ms": statistics.median(spreads) if spreads else None,
        "actual_sync_modes": notes,
        "h2_available": "h2_single_packet" in notes,
    }


async def main():
    process, port = _start("wallet_race_vulnerable")
    try:
        rows = []
        for mode in MODES:
            rows.append(await one_mode(port, mode))
        print(json.dumps(rows, indent=2))
        print("\n| Mode | FAIL runs | FAIL rate | Median spread (ms) | Rounds to first hit |")
        print("| --- | ---: | ---: | ---: | --- |")
        for row in rows:
            hits = row["first_hit_rounds"]
            first = f"{min(hits)}" if hits else "none"
            spread = f"{row['median_spread_ms']:.6f}" if row["median_spread_ms"] is not None else "n/a"
            print(f"| {row['mode']} | {row['fails']}/{row['runs']} | {row['fail_rate'] * 100:.0f}% | {spread} | {first} |")
    finally:
        process.terminate()
        process.wait(timeout=3)


if __name__ == "__main__":
    asyncio.run(main())
