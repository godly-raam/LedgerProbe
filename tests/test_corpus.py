"""End-to-end regression test suite for LedgerProbe against the authorization fixture corpus."""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
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


async def execute_profile(profile_name: str, tmp_path: Path, app=None) -> tuple[int, dict, Path, Path]:
    """Execute a single profile end-to-end through the real CLI path against the fixture server."""
    profile_spec = EXPECTATIONS[profile_name]
    rule_file = FIXTURES_DIR / profile_spec["rule_file"]
    sarif_path = tmp_path / "results.sarif"
    junit_path = tmp_path / "results.xml"

    if app is None:
        app = create_app(profile=profile_name, timeout_delay=0.15)
    transport = TimingOutASGITransport(app=app)

    def client_factory(**kwargs):
        kwargs["max_rps"] = 10000
        kwargs["transport"] = transport
        return GuardedClient(**kwargs)

    cli_timeout = 0.05 if profile_name in {"slow_timeout", "control_timeout"} else 5.0
    cli_args = [
        "--spec", str(SPEC_PATH),
        "--base-url", "http://authz.test",
        "--rules", str(rule_file),
        "--inputs", str(INPUTS_PATH),
        "--timeout", str(cli_timeout),
        "--sarif", str(sarif_path),
        "--junit", str(junit_path),
    ]
    if profile_spec.get("read_only", True):
        cli_args.append("--read-only")
    cli_args.extend(profile_spec.get("extra_args", []))
    if profile_spec.get("spec_check"):
        cli_args.extend(["--spec-check", profile_spec["spec_check"]])
    args = ledgerprobe.arguments(cli_args)

    observed = []
    original_run_rules = ledgerprobe.run_rules

    async def recording(*a, **kw):
        results = await original_run_rules(*a, **kw)
        observed.extend(results)
        return results

    with patch.object(ledgerprobe, "GuardedClient", side_effect=client_factory), \
         patch.object(ledgerprobe, "run_rules", side_effect=recording):
        exit_code = await ledgerprobe.execute(args)

    expected = profile_spec.get("expected_findings", 1)
    assert len(observed) == expected, (
        f"Expected {expected} finding result(s) for profile {profile_name}, got {len(observed)}")
    return exit_code, observed[0] if expected == 1 else observed, sarif_path, junit_path


CORPUS_EXPECTATIONS = {name: spec for name, spec in EXPECTATIONS.items()
                       if "expected_findings" not in spec}


@pytest.mark.parametrize("profile_name,profile_spec", list(CORPUS_EXPECTATIONS.items()),
                         ids=list(CORPUS_EXPECTATIONS))
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
    elif expected_verdict == "SKIPPED":
        assert exit_code == 2, f"Profile {profile_name} expected exit code 2 on SKIPPED, got {exit_code}"
    elif expected_verdict == "ERROR":
        assert exit_code == 2, f"Profile {profile_name} expected exit code 2 on ERROR, got {exit_code}"
    if "expected_exit" in profile_spec:
        assert exit_code == profile_spec["expected_exit"], (
            f"Profile {profile_name}: expected exit {profile_spec['expected_exit']}, got {exit_code}"
        )

    # Ensure sensitive canaries and context credentials are never leaked into reports
    sarif_content = sarif_path.read_text(encoding="utf-8")
    junit_content = junit_path.read_text(encoding="utf-8")
    for secret in ("canary-secret-owner-9988", "token-owner", "token-other"):
        assert secret not in sarif_content, f"Sensitive secret '{secret}' leaked in SARIF for {profile_name}"
        assert secret not in junit_content, f"Sensitive secret '{secret}' leaked in JUnit for {profile_name}"

    if "expected_spec_drift" in profile_spec:
        drift = profile_spec["expected_spec_drift"]
        assert result.get("spec_drift") == drift
        assert drift in sarif_content
        assert drift in junit_content


def test_fixed_list_has_owner_positive_baseline():
    import httpx
    async def check():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(profile="bola_list_filter_fixed")),
                                     base_url="http://authz.test") as client:
            owner = await client.get("/api/v1/items?owner_id=user_owner", headers={"Authorization": "Bearer token-owner"})
            other = await client.get("/api/v1/items?owner_id=user_owner", headers={"Authorization": "Bearer token-other"})
        assert owner.status_code == 200 and owner.json()
        assert owner.json()[0]["canary"] == "canary-secret-owner-9988"
        assert other.status_code == 403 or other.json() == []
    asyncio.run(check())


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


def test_mutation_restore_returns_owner_state(tmp_path: Path):
    app = create_app(profile="mutation_idempotent_restore")
    before = copy.deepcopy(app.state.authz.objects)
    exit_code, result, _, _ = asyncio.run(execute_profile("mutation_idempotent_restore", tmp_path, app=app))
    assert exit_code == 1
    assert result["verdict"] == "FAIL"
    assert app.state.authz.objects == before


def test_access_matrix_expands_to_distinct_checks(tmp_path: Path):
    code, results, _, _ = asyncio.run(execute_profile("access_matrix_expansion", tmp_path))
    assert code == 1
    assert [row["verdict"] for row in results] == ["FAIL", "PASS"]
    assert len({row["rule_id"] for row in results}) == 2
    assert all(row["rule_id"].endswith("#user") for row in results)
    assert len({row["fingerprint"] for row in results}) == 2
    assert all(row["check_type"] == "bfla" for row in results)


def test_mutation_marker_is_not_serialized(tmp_path: Path):
    app = create_app(profile="mutate_vuln_marker")
    _, result, sarif_path, junit_path = asyncio.run(execute_profile("mutate_vuln_marker", tmp_path, app=app))
    marker = app.state.authz.last_marker
    assert marker
    assert result["evidence"]["marker_hash"] == hashlib.sha256(marker.encode()).hexdigest()
    assert marker not in sarif_path.read_text(encoding="utf-8")
    assert marker not in junit_path.read_text(encoding="utf-8")
    assert marker not in json.dumps(result)
