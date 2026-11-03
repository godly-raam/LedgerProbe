from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from pkg.suppressions import apply_suppressions, load_suppressions

FP = "lp1:" + "a" * 64
TODAY = date(2026, 11, 3)


def _entry(**changes):
    value = {
        "fingerprint": FP, "reason": "Accepted temporary customer exception",
        "owner": "security-team", "created": TODAY - timedelta(days=10),
        "expires": TODAY + timedelta(days=10), "ticket": "SEC-1",
        "approved_by": "security-lead",
    }
    value.update(changes)
    return value


def _result(**changes):
    value = {"fingerprint": FP, "rule_id": "ownership", "severity": "high",
             "status": "failed", "verdict": "FAIL"}
    value.update(changes)
    return value


def test_active_suppression_and_boundary_and_expiry():
    output, stats, warnings = apply_suppressions([_result()], [_entry(expires=TODAY)], today=TODAY)
    assert output[0]["status"] == "suppressed"
    assert output[0]["suppression"]["owner"] == "security-team"
    assert stats == {"active": 1, "expired": 0, "stale": 0}
    assert warnings == []
    output, stats, warnings = apply_suppressions(
        [_result()], [_entry(expires=TODAY - timedelta(days=1))], today=TODAY)
    assert output[0]["status"] == "failed"
    assert stats == {"active": 0, "expired": 1, "stale": 0}
    assert warnings == [{"code": "suppression_expired", "owner": "security-team",
                         "expires": (TODAY - timedelta(days=1)).isoformat()}]


def test_stale_suppression_is_reported_and_error_cannot_be_suppressed():
    other = "lp1:" + "b" * 64
    output, stats, warnings = apply_suppressions(
        [_result(status="error", severity="low")], [_entry()], today=TODAY)
    assert output[0]["status"] == "error"
    assert stats["active"] == 0
    assert stats["stale"] == 0
    assert warnings == []
    output, stats, warnings = apply_suppressions([], [_entry(fingerprint=other)], today=TODAY)
    assert stats == {"active": 0, "expired": 0, "stale": 1}
    assert warnings == [{"code": "stale_suppression", "fingerprint": other}]


def test_high_and_critical_require_ticket_and_approval():
    for severity in ("high", "critical"):
        with pytest.raises(ValueError):
            apply_suppressions([_result(severity=severity)], [_entry(ticket=None)], today=TODAY)
        with pytest.raises(ValueError):
            apply_suppressions([_result(severity=severity)], [_entry(approved_by=None)], today=TODAY)
    output, _, _ = apply_suppressions([_result(severity="medium")],
                                      [_entry(ticket=None, approved_by=None)], today=TODAY)
    assert output[0]["status"] == "suppressed"


def test_suppression_file_is_strict(tmp_path: Path):
    path = tmp_path / "suppressions.yaml"
    path.write_text(yaml.safe_dump([_entry()]))
    assert load_suppressions(path, max_days=180)[0]["fingerprint"] == FP
    invalid = [
        [_entry(reason="too short")],
        [_entry(owner=" ")],
        [_entry(fingerprint="sha256:" + "a" * 64)],
        [_entry(created=TODAY, expires=TODAY + timedelta(days=181))],
        [_entry(expires=TODAY - timedelta(days=1), created=TODAY)],
        [_entry(extra="unknown")],
        [_entry(), _entry()],
        {"wrong": []},
    ]
    for document in invalid:
        path.write_text(yaml.safe_dump(document))
        with pytest.raises(ValueError):
            load_suppressions(path, max_days=180)
    path.write_text("suppressions: [")
    with pytest.raises(ValueError):
        load_suppressions(path)
    assert load_suppressions(tmp_path / "absent.yaml") == []
