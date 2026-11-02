from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import yaml

import ledgerprobe
from pkg.rules.verdict import evaluate_race

FIXTURES = Path(__file__).parent / "fixtures" / "race_server"
EXPECTATIONS = yaml.safe_load((FIXTURES / "expectations.yaml").read_text(encoding="utf-8"))


def _free_port() -> int:
    try:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]
    except OSError as exc:
        pytest.skip(f"loopback binding unavailable: {exc}")


def _start(profile: str):
    port = _free_port()
    env = {**os.environ, "RACE_PROFILE": profile}
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "tests.fixtures.race_server.app:app",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=Path(__file__).parent.parent, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 8
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
    raise RuntimeError(f"race fixture did not start: {stderr[-1000:]}")


@pytest.mark.parametrize("profile,spec", list(EXPECTATIONS.items()), ids=list(EXPECTATIONS))
def test_race_corpus(profile: str, spec: dict, tmp_path: Path):
    process, port = _start(profile)
    observed = []
    try:
        args = ledgerprobe.arguments([
            "--spec", str(FIXTURES / "openapi.json"),
            "--base-url", f"http://127.0.0.1:{port}",
            "--rules", str(FIXTURES / spec["rule_file"]),
            "--inputs", str(FIXTURES / "inputs.json"),
            "--sarif", str(tmp_path / "results.sarif"),
            "--junit", str(tmp_path / "results.xml"),
            "--timeout", "5", "--max-rps", "10000",
            "--spec-check", "warn",
            *spec.get("extra_args", []),
        ])
        original = ledgerprobe.run_rules

        async def recording(*a, **kw):
            results = await original(*a, **kw)
            observed.extend(results)
            return results

        with patch.object(ledgerprobe, "run_rules", side_effect=recording):
            exit_code = asyncio.run(ledgerprobe.execute(args))
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()

    assert len(observed) == 1
    result = observed[0]
    assert result["verdict"] == spec["expected_verdict"], result
    assert result.get("reason") == spec["expected_reason"], result
    assert result.get("note") == spec["expected_note"], result
    if spec["expected_verdict"] == "FAIL":
        assert exit_code == 1
    elif spec["expected_verdict"] == "INCONCLUSIVE":
        assert exit_code == 0
    elif spec["expected_verdict"] == "SKIPPED":
        assert exit_code == 2
    text = (tmp_path / "results.sarif").read_text() + (tmp_path / "results.xml").read_text()
    for secret in ("balance", "100", "token-owner", "token-other", "Idempotency-Key"):
        assert secret not in text


def test_race_report_has_no_marker_or_balance_values(tmp_path: Path):
    process, port = _start("wallet_race_vulnerable")
    try:
        result = asyncio.run(_run_direct(port, "rules_race_wallet.yaml", tmp_path))
    finally:
        process.terminate()
        process.wait(timeout=3)
    assert result["verdict"] == "FAIL"
    text = (tmp_path / "results.sarif").read_text() + (tmp_path / "results.xml").read_text()
    for secret in ("balance", "100", "token-owner", "token-other", "race-canary"):
        assert secret not in text


async def _run_direct(port: int, rule_file: str, tmp_path: Path):
    observed = []
    args = ledgerprobe.arguments([
        "--spec", str(FIXTURES / "openapi.json"),
        "--base-url", f"http://127.0.0.1:{port}",
        "--rules", str(FIXTURES / rule_file),
        "--inputs", str(FIXTURES / "inputs.json"),
        "--sarif", str(tmp_path / "results.sarif"),
        "--junit", str(tmp_path / "results.xml"),
        "--timeout", "5", "--max-rps", "10000", "--allow-mutations",
        "--spec-check", "warn",
    ])
    original = ledgerprobe.run_rules

    async def recording(*a, **kw):
        results = await original(*a, **kw)
        observed.extend(results)
        return results

    with patch.object(ledgerprobe, "run_rules", side_effect=recording):
        await ledgerprobe.execute(args)
    return observed[0]


def _round(spread=1.0, accepted=1, initial=100, final=90, counts=None, unavailable=False):
    return {"spread_ms": spread, "accepted": accepted, "initial": initial,
            "final": final, "status_counts": counts or {}, "verify_unavailable": unavailable}


def test_race_verdict_violation_and_pass():
    invariant = {"max_successes": 1, "ledger": {"delta_per_success": -10,
                                                "max_total_effect": 10}}
    failed = evaluate_race(rounds=[_round(accepted=10, final=0) for _ in range(5)],
                           requests=10, max_spread_ms=5, invariant=invariant)
    assert (failed["verdict"], failed["reason"]) == ("FAIL", "race_invariant_violated")
    passed = evaluate_race(rounds=[_round() for _ in range(5)],
                           requests=10, max_spread_ms=5, invariant=invariant)
    assert (passed["verdict"], passed["note"]) == ("PASS", "no_violation_observed")


def test_race_verdict_weak_and_errors():
    invariant = {"max_successes": 1}
    weak = evaluate_race(rounds=[_round(spread=20) for _ in range(5)],
                         requests=10, max_spread_ms=5, invariant=invariant)
    assert (weak["verdict"], weak["reason"]) == ("INCONCLUSIVE", "weak_synchronization")
    limited = evaluate_race(rounds=[_round(counts={"429": 10}) for _ in range(5)],
                            requests=10, max_spread_ms=5, invariant=invariant)
    assert (limited["verdict"], limited["reason"]) == ("INCONCLUSIVE", "rate_limited")
    reset = evaluate_race(rounds=[], requests=10, max_spread_ms=5,
                          invariant=invariant, reset_failed=True)
    assert (reset["verdict"], reset["reason"]) == ("INCONCLUSIVE", "reset_failed")


def test_race_verdict_restore_failure():
    result = evaluate_race(rounds=[], requests=10, max_spread_ms=5,
                           invariant={"max_successes": 1}, restore_failed=True)
    assert (result["verdict"], result["reason"]) == ("ERROR", "restore_failed")
