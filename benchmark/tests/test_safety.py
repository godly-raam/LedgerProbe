"""Hard-fail tests for the benchmark target allowlist and scorer."""

from __future__ import annotations

import pytest

from benchmark.run import UnsafeTarget, _score, validate_target_url


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:5001",
    "http://127.0.0.1",
    "https://localhost:8443/identity",
    "http://[::1]:8888",
    "http://127.10.20.30:9000",
])
def test_loopback_is_allowed(url: str):
    assert validate_target_url(url) == url


@pytest.mark.parametrize("url", [
    "https://example.com",
    "http://8.8.8.8",
    "http://127.0.0.1.evil.test",
    "http://localhost.evil.test",
    "http://169.254.169.254/latest/meta-data",
    "http://0.0.0.0:8000",
    "http://[::ffff:8.8.8.8]",
    "http://user:pass@127.0.0.1:8000",
    "ftp://127.0.0.1:8000",
    "http://127.0.0.1:0",
    "http://127.0.0.1:70000",
    "http:///missing-host",
    "",
])
def test_public_or_malformed_targets_hard_fail(url: str):
    with pytest.raises(UnsafeTarget):
        validate_target_url(url)


def test_docker_private_addresses_require_explicit_opt_in():
    with pytest.raises(UnsafeTarget):
        validate_target_url("http://172.17.0.2:8000")
    assert validate_target_url("http://172.17.0.2:8000", allow_docker_internal=True)
    with pytest.raises(UnsafeTarget):
        validate_target_url("http://crapi-identity:8080", allow_docker_internal=True)
    assert validate_target_url("http://crapi-identity:8080", allow_docker_internal=True,
                               docker_hosts=("crapi-identity",))


def test_scorer_never_counts_inconclusive_as_correct():
    cases = [
        {"rule_id": "v1", "instance": "i", "method": "GET", "path": "/v1",
         "label": "vulnerable", "source": "s"},
        {"rule_id": "v2", "instance": "i", "method": "GET", "path": "/v2",
         "label": "vulnerable", "source": "s"},
        {"rule_id": "v3", "instance": "i", "method": "GET", "path": "/v3",
         "label": "vulnerable", "source": "s"},
        {"rule_id": "s1", "instance": "i", "method": "GET", "path": "/s1",
         "label": "safe", "source": "s"},
        {"rule_id": "s2", "instance": "i", "method": "GET", "path": "/s2",
         "label": "safe", "source": "s"},
    ]
    results = {
        "v1": {"verdict": "FAIL", "reason": "leak_detected"},
        "v2": {"verdict": "PASS", "reason": "denied"},
        "v3": {"verdict": "INCONCLUSIVE", "reason": "ambiguous_2xx"},
        "s1": {"verdict": "PASS", "reason": ""},
        "s2": {"verdict": "INCONCLUSIVE", "reason": "ambiguous_2xx"},
    }
    summary = _score(cases, results, "i")
    assert summary["counts"] == {"TP": 1, "FP": 0, "TN": 1, "FN": 1,
                                 "INC_VULN": 1, "INC_SAFE": 1}
    assert sum(summary["counts"].values()) == len(cases)
    assert summary["precision"] == 1.0
    assert summary["recall"] == pytest.approx(1 / 3)
    assert summary["recall_excl_inconclusive"] == 0.5
