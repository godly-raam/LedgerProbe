from __future__ import annotations

import json
from pathlib import Path

import pytest

import ledgerprobe
from pkg.cvss import DEFAULT_VECTORS, score_vector
from pkg.fingerprints import fingerprint
from pkg.results import (
    SCHEMA_VERSION, apply_baseline, build_document, diff_documents, gate_exit,
    load_document, write_document,
)


def _result(rule_id="ownership", method="GET", path="/objects/{id}", status="failed"):
    fp = fingerprint(rule_id=rule_id, method=method, path_template=path,
                     identity_roles=["owner", "other"], check_type="bola")
    return {"rule_id": rule_id, "method": method, "path": path, "path_template": path,
            "check_type": "bola", "identity_roles": ["owner", "other"],
            "fingerprint": fp, "status": status, "verdict": "FAIL" if status == "failed" else "PASS",
            "severity": "high", "confidence": "high",
            "cvss": score_vector(DEFAULT_VECTORS["bola"]), "evidence": {"overlap_count": 2}}


def _document(results):
    return build_document(results, target="https://target.test",
                          modes={"read_only": True}, timestamp="2026-11-03T00:00:00+00:00")


def test_new_unchanged_resolved_and_gate_matrix(tmp_path):
    old_result = _result()
    old = _document([old_result])
    new_result = _result(rule_id="new-rule")
    current, stats = apply_baseline([new_result], old)
    assert stats == {"new": 1, "unchanged": 0, "resolved": 1}
    assert current[0]["baseline_status"] == "new"
    assert gate_exit(current, fail_on="new") == 1
    assert gate_exit(current, fail_on="any") == 1
    assert gate_exit(current, fail_on="none") == 0
    current, stats = apply_baseline([old_result], old)
    assert stats == {"new": 0, "unchanged": 1, "resolved": 0}
    assert current[0]["baseline_status"] == "unchanged"
    assert gate_exit(current, fail_on="new") == 0
    diff = diff_documents(old, _document([new_result]))
    assert [item["rule_id"] for item in diff["new"]] == ["new-rule"]
    assert [item["rule_id"] for item in diff["resolved"]] == ["ownership"]
    assert diff["unchanged"] == []


def test_suppressed_and_error_statuses_do_not_fail_the_gate():
    suppressed = {**_result(), "status": "suppressed"}
    assert gate_exit([suppressed], fail_on="any") == 0
    error = {**_result(), "status": "error"}
    assert gate_exit([error], fail_on="none") == 2
    assert gate_exit([], fail_on="none") == 2
    passed = {**_result(), "status": "passed"}
    assert gate_exit([passed], fail_on_stale=True, stale=1) == 1


def test_baseline_schema_mismatch_is_a_clear_error(tmp_path):
    path = tmp_path / "old.json"
    path.write_text(json.dumps({"schema_version": "ledgerprobe-results/0", "findings": []}))
    with pytest.raises(ValueError, match="schema mismatch"):
        load_document(path)
    path.write_text("not json")
    with pytest.raises(ValueError, match="could not be read"):
        load_document(path)
    assert SCHEMA_VERSION == "ledgerprobe-results/1"
    good = tmp_path / "good.json"
    write_document(_document([_result()]), good)
    assert ledgerprobe.main(["diff", str(path), str(good)]) == 2


def test_write_document_round_trip(tmp_path):
    path = tmp_path / "results.json"
    document = _document([_result()])
    write_document(document, path)
    assert load_document(path)["findings"][0]["fingerprint"] == _result()["fingerprint"]
