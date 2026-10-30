"""End-to-end regression test suite for LedgerProbe against the authorization fixture corpus."""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch
import pytest

from pkg.guardrails import GuardedClient
import ledgerprobe
import pkg.rules.verdict as verdict_module
from tests.fixtures.authz_server import (
    FIXTURES_DIR,
    INPUTS_PATH,
    SPEC_PATH,
    TimingOutASGITransport,
    create_app,
    load_expectations,
)

EXPECTATIONS = load_expectations()


async def execute_profile(profile_name: str, tmp_path: Path) -> tuple[int, dict, Path, Path]:
    """Execute a single profile end-to-end through the real CLI path against the fixture server."""
    profile_spec = EXPECTATIONS[profile_name]
    rule_file = FIXTURES_DIR / profile_spec["rule_file"]
    sarif_path = tmp_path / "results.sarif"
    junit_path = tmp_path / "results.xml"

    app = create_app(profile=profile_name, timeout_delay=0.15)
    transport = TimingOutASGITransport(app=app)

    def client_factory(**kwargs):
        kwargs["max_rps"] = 10000
        kwargs["transport"] = transport
        return GuardedClient(**kwargs)

    cli_timeout = 0.05 if profile_name == "slow_timeout" else 5.0
    args = ledgerprobe.arguments([
        "--spec", str(SPEC_PATH),
        "--base-url", "http://authz.test",
        "--rules", str(rule_file),
        "--inputs", str(INPUTS_PATH),
        "--timeout", str(cli_timeout),
        "--read-only",
        "--sarif", str(sarif_path),
        "--junit", str(junit_path),
    ])

    observed = []
    original_run_rules = ledgerprobe.run_rules

    async def recording(*a, **kw):
        results = await original_run_rules(*a, **kw)
        observed.extend(results)
        return results

    with patch.object(ledgerprobe, "GuardedClient", side_effect=client_factory), \
         patch.object(ledgerprobe, "run_rules", side_effect=recording):
        exit_code = await ledgerprobe.execute(args)

    assert len(observed) == 1, f"Expected 1 finding result for profile {profile_name}, got {len(observed)}"
    return exit_code, observed[0], sarif_path, junit_path


@pytest.mark.parametrize("profile_name,profile_spec", list(EXPECTATIONS.items()), ids=list(EXPECTATIONS.keys()))
def test_corpus_profile(profile_name: str, profile_spec: dict, tmp_path: Path):
    """Test that every fixture profile matches its exact expected verdict, reason, and note."""
    exit_code, result, sarif_path, junit_path = asyncio.run(execute_profile(profile_name, tmp_path))

    expected_verdict = profile_spec["expected_verdict"]
    expected_reason = profile_spec["expected_reason"]
    expected_note = profile_spec["expected_note"]

    # Assert exact verdict, reason, and note
    assert result["verdict"] == expected_verdict, (
        f"Profile {profile_name}: expected verdict {expected_verdict}, got {result['verdict']}"
    )
    assert result.get("reason") == expected_reason, (
        f"Profile {profile_name}: expected reason {expected_reason}, got {result.get('reason')}"
    )
    assert result.get("note") == expected_note, (
        f"Profile {profile_name}: expected note {expected_note}, got {result.get('note')}"
    )
    if "expected_confidence" in profile_spec:
        assert result.get("confidence") == profile_spec["expected_confidence"], (
            f"Profile {profile_name}: expected confidence {profile_spec['expected_confidence']}, got {result.get('confidence')}"
        )

    # Validate CLI exit code contracts
    if expected_verdict == "FAIL":
        assert exit_code == 1, f"Profile {profile_name} expected exit code 1 on FAIL, got {exit_code}"
    elif expected_verdict == "PASS":
        assert exit_code == 0, f"Profile {profile_name} expected exit code 0 on PASS, got {exit_code}"
    elif expected_verdict == "INCONCLUSIVE":
        assert exit_code == 0, f"Profile {profile_name} expected exit code 0 on default INCONCLUSIVE, got {exit_code}"

    # Ensure sensitive canaries and context credentials are never leaked into reports
    sarif_content = sarif_path.read_text(encoding="utf-8")
    junit_content = junit_path.read_text(encoding="utf-8")
    for secret in ("canary-secret-owner-9988", "token-owner", "token-other"):
        assert secret not in sarif_content, f"Sensitive secret '{secret}' leaked in SARIF for {profile_name}"
        assert secret not in junit_content, f"Sensitive secret '{secret}' leaked in JUnit for {profile_name}"


def test_mutation_guard_catches_broken_overlap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Mutation test: breaking the engine's overlap logic causes a vulnerable corpus test to fail."""
    # Monkeypatch the engine's value extraction so overlap is always empty
    monkeypatch.setattr(verdict_module, "_values", lambda resp, ignored: set())

    exit_code, result, _, _ = asyncio.run(execute_profile("bola_plain", tmp_path))

    # A broken overlap detector causes bola_plain to become INCONCLUSIVE instead of FAIL
    assert result["verdict"] != "FAIL", "Broken overlap logic should not detect the leak"
    with pytest.raises(AssertionError):
        # Proves that the corpus expectation would fail on this regression
        assert result["verdict"] == EXPECTATIONS["bola_plain"]["expected_verdict"]
