from __future__ import annotations

import json
import asyncio
from pathlib import Path
from xml.etree import ElementTree as ET

import jsonschema
import pytest
import httpx
from unittest.mock import AsyncMock

from pkg.cvss import DEFAULT_VECTORS, score_vector
from pkg.fingerprints import (
    check_type, fingerprint, identity_roles, result_fingerprint,
)
from pkg.reporter import write_junit, write_sarif
from pkg.results import SCHEMA_VERSION, build_document, write_document
from pkg.rules import run_rules

SCHEMA = json.loads((Path(__file__).parents[1] / "schemas" / "results.schema.json").read_text())
VALIDATOR = jsonschema.Draft202012Validator(
    SCHEMA, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER)


def _result(*, status="failed", fingerprint_value=None, confidence="high", note=None,
            severity="high", role=("owner", "other")):
    value = {
        "rule_id": "ownership", "name": "Object isolation", "severity": severity,
        "owasp_category": "API1:2023", "cvss_score": 8.1,
        "path": "/objects/{object_id}", "path_template": "/objects/{object_id}",
        "method": "GET", "check_type": "bola", "identity_roles": sorted(role),
        "cvss": score_vector(DEFAULT_VECTORS["bola"]),
        "status": status, "verdict": {"failed": "FAIL", "suppressed": "FAIL",
                                      "skipped": "SKIPPED", "error": "ERROR"}.get(status, "PASS"),
        "confidence": confidence, "evidence": {"overlap_count": 2, "confirm_runs": 2},
    }
    if note:
        value["note"] = note
    value["fingerprint"] = fingerprint_value or fingerprint(
        rule_id=value["rule_id"], method=value["method"],
        path_template=value["path_template"], identity_roles=value["identity_roles"],
        check_type=value["check_type"])
    return value


def test_fingerprint_is_stable_across_objects_tokens_hosts_ports_and_confidence():
    first = fingerprint(rule_id="ownership", method="GET", path_template="/objects/{object_id}",
                        identity_roles=["other", "owner"], check_type="bola")
    second = fingerprint(rule_id="ownership", method="GET", path_template="/objects/{object_id}",
                         identity_roles=["owner", "other"], check_type="bola")
    assert first == second
    # The function's inputs deliberately contain no object value, token, host or port.
    assert result_fingerprint(_result()) == _result()["fingerprint"]
    assert result_fingerprint(_result(confidence="reduced")) == _result()["fingerprint"]
    assert result_fingerprint(_result(confidence="high", note="soft_deny")) == _result()["fingerprint"]


def test_fingerprint_changes_for_each_identity_component():
    baseline = fingerprint(rule_id="ownership", method="GET", path_template="/objects/{object_id}",
                           identity_roles=["other", "owner"], check_type="bola")
    changes = [
        fingerprint(rule_id="other", method="GET", path_template="/objects/{object_id}",
                    identity_roles=["other", "owner"], check_type="bola"),
        fingerprint(rule_id="ownership", method="POST", path_template="/objects/{object_id}",
                    identity_roles=["other", "owner"], check_type="bola"),
        fingerprint(rule_id="ownership", method="GET", path_template="/objects/{object_id}/x",
                    identity_roles=["other", "owner"], check_type="bola"),
        fingerprint(rule_id="ownership", method="GET", path_template="/objects/{object_id}",
                    identity_roles=["other"], check_type="bola"),
        fingerprint(rule_id="ownership", method="GET", path_template="/objects/{object_id}",
                    identity_roles=["other", "owner"], check_type="state_change"),
    ]
    assert all(value != baseline for value in changes)
    with pytest.raises(ValueError):
        fingerprint(rule_id="x", method="GET", path_template="/x", identity_roles=[],
                    check_type="unknown")


def test_fingerprint_stable_across_actual_object_values_and_hosts():
    rule = {"id": "ownership", "name": "Object isolation", "severity": "high",
            "owasp_category": "API1:2023", "cvss_score": 8.1,
            "target_endpoints": [{"path": "/objects/{id}", "method": "GET"}],
            "auth_contexts": {"primary": "owner", "forbidden": "other"},
            "assertions": [{"type": "status_code", "expected": 403}]}
    inventory = {"endpoints": [{"path": "/objects/{id}", "method": "GET",
                                "operation_id": "get", "parameters": [
                                    {"name": "id", "in": "path", "required": True}],
                                "request_body": None}], "graph": []}

    async def run(base, value):
        client = AsyncMock()
        client.request.side_effect = [httpx.Response(200), httpx.Response(403)]
        result = (await run_rules({**inventory, "base_url": base}, [rule], client,
                                  {"owner": {"Authorization": "owner-token"},
                                   "other": {"Authorization": "other-token"}},
                                  {"id": value}))[0]
        assert value not in json.dumps(result)
        return result["fingerprint"]

    assert asyncio.run(run("https://one.test", "OBJECT-ONE")) == asyncio.run(
        run("https://two.test:8443", "OBJECT-TWO"))


def test_check_type_mapping_and_roles_never_include_tokens():
    assert check_type({"race": {}, "auth_contexts": {"primary": "owner", "forbidden": "other"}}) == "race"
    assert check_type({"mutating": True}) == "state_change"
    assert check_type({"leak_detection": {}, "scope": "caller"}) == "caller_scope"
    assert check_type({"leak_detection": {}, "scope": "shared"}) == "shared_scope"
    assert check_type({"leak_detection": {}}) == "bola"
    assert check_type({"auth_contexts": {"forbidden": "other"}}) == "unauthenticated_access"
    assert identity_roles({"auth_contexts": {"primary": "owner", "forbidden": "other"}}) == ["other", "owner"]


def test_schema_document_validates_and_contains_no_secret_values(tmp_path):
    failed = _result()
    skipped = _result(status="skipped", note="caller_scoped")
    error = _result(status="error")
    suppressed = _result(status="suppressed")
    suppressed["suppression"] = {"owner": "security-team", "reason": "Accepted test exception",
                                  "expires": "2026-12-31"}
    document = build_document(
        [failed, skipped, error, suppressed],
        target="https://target.test", modes={"read_only": False, "allow_mutations": True,
                                             "spec_check": "warn"},
        warnings=[{"code": "suppression_expired", "owner": "security-team", "expires": "2026-01-01"}],
        baseline={"new": 1, "unchanged": 0, "resolved": 0},
        suppressions={"active": 1, "expired": 0, "stale": 0},
        timestamp="2026-11-03T00:00:00+00:00",
    )
    VALIDATOR.validate(document)
    assert document["schema_version"] == SCHEMA_VERSION
    assert document["run"]["target"] == "https://target.test"
    assert document["findings"][0]["fingerprint"].startswith("lp1:")
    assert document["findings"][1]["status"] == "suppressed"
    assert document["warnings"][0]["code"] == "suppression_expired"
    text = json.dumps(document)
    for secret in ("object-123", "Bearer", "token-owner", "race-canary"):
        assert secret not in text
    write_document(document, tmp_path / "results.json")
    VALIDATOR.validate(json.loads((tmp_path / "results.json").read_text()))


def test_json_sarif_and_junit_emit_the_same_fingerprint(tmp_path):
    result = _result()
    path = tmp_path / "results.json"
    write_document(build_document([result], target="https://target.test",
                                  modes={"read_only": True}), path)
    sarif = tmp_path / "results.sarif"
    junit = tmp_path / "results.xml"
    write_sarif([result], sarif)
    write_junit([result], junit)
    fp = result["fingerprint"]
    assert json.loads(path.read_text())["findings"][0]["fingerprint"] == fp
    assert json.loads(sarif.read_text())["runs"][0]["results"][0]["partialFingerprints"] == {
        "ledgerprobe/v1": fp}
    properties = ET.parse(junit).find(".//property[@name='ledgerprobe.fingerprint']")
    assert properties is not None and properties.get("value") == fp


def test_suppressed_sarif_and_junit_representation(tmp_path):
    result = _result(status="suppressed")
    result["suppression"] = {"owner": "security-team", "reason": "Accepted test exception",
                             "expires": "2026-12-31"}
    sarif = tmp_path / "suppressed.sarif"
    junit = tmp_path / "suppressed.xml"
    write_sarif([result], sarif)
    write_junit([result], junit)
    finding = json.loads(sarif.read_text())["runs"][0]["results"][0]
    assert finding["suppressions"] == [{"kind": "external", "justification": "Accepted test exception"}]
    suite = ET.parse(junit).getroot()
    assert suite.get("skipped") == "1"
    assert suite.find(".//skipped").get("message") == "Suppressed: Accepted test exception"
