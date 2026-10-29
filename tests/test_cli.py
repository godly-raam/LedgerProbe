import asyncio
import json
from pathlib import Path
from unittest.mock import patch
from xml.etree import ElementTree as ET

import httpx
import pytest

import ledgerprobe
from pkg.guardrails import GuardedClient


SPEC = {
    "openapi": "3.1.0", "info": {"title": "Test", "version": "1.0"},
    "servers": [{"url": "https://target.test"}],
    "paths": {"/objects/{id}": {"get": {
        "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
        "responses": {"200": {"description": "Object"}},
    }}},
}
RULE = {
    "id": "ownership", "name": "Ownership", "severity": "HIGH", "owasp_category": "API1:2023",
    "cvss_score": 8.1, "target_endpoints": [{"path": "/objects/{id}", "method": "GET"}],
    "auth_contexts": {"primary": "owner", "forbidden": "other"},
    "assertions": [{"type": "status_code", "expected": 403}],
}


def scan(tmp_path, handler, *, rule=None, spec=None, inputs=None, extra=()):
    for name, data in [("spec.json", spec or SPEC), ("rules.json", rule or RULE), ("inputs.json", inputs or {
        "contexts": {"owner": {"Authorization": "owner-secret"}, "other": {"Authorization": "other-secret"}},
        "variables": {"id": "object-1"},
    })]:
        (tmp_path / name).write_text(json.dumps(data))
    args = ledgerprobe.arguments([
        "--spec", str(tmp_path / "spec.json"), "--rules", str(tmp_path / "rules.json"),
        "--inputs", str(tmp_path / "inputs.json"), "--sarif", str(tmp_path / "results.sarif"),
        "--junit", str(tmp_path / "results.xml"), "--max-rps", "10000", *extra,
    ])
    def client(**kwargs):
        return GuardedClient(transport=httpx.MockTransport(handler), **kwargs)
    with patch.object(ledgerprobe, "GuardedClient", side_effect=client):
        code = asyncio.run(ledgerprobe.execute(args))
    sarif = json.loads((tmp_path / "results.sarif").read_text())
    junit = ET.parse(tmp_path / "results.xml")
    return code, sarif, junit


@pytest.mark.parametrize("forbidden_status,exit_code,findings", [(403, 0, 0), (200, 1, 1)])
def test_spec_to_ci_reports(tmp_path, forbidden_status, exit_code, findings):
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(200 if request.headers["Authorization"] == "owner-secret" else forbidden_status, json={"id": "object-1"})
    code, sarif, junit = scan(tmp_path, handler, extra=("--read-only",))
    assert code == exit_code
    assert len(sarif["runs"][0]["results"]) == findings
    assert len(junit.findall(".//failure")) == findings
    assert [r.headers["Authorization"] for r in requests] == ["owner-secret", "other-secret"]
    assert all(r.url.path == "/objects/object-1" for r in requests)
    assert "owner-secret" not in json.dumps(sarif)


def test_failed_baseline_is_error_not_security_finding(tmp_path):
    code, sarif, junit = scan(tmp_path, lambda request: httpx.Response(401))
    assert code == 2
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False
    assert len(junit.findall(".//error")) == 1


def test_read_only_blocks_mutation_before_any_http(tmp_path):
    rule = {**RULE, "target_endpoints": [{"path": "/objects", "method": "POST"}]}
    spec = {**SPEC, "paths": {"/objects": {"post": {"responses": {"200": {"description": "Created"}}}}}}
    def no_http(request):
        pytest.fail("blocked scan must not contact target")
    code, sarif, junit = scan(tmp_path, no_http, rule=rule, spec=spec, extra=("--read-only",))
    assert code == 2
    assert sarif["runs"][0]["results"] == []
    assert len(junit.findall(".//skipped")) == 1


def test_explicit_override_reaches_only_chosen_target(tmp_path):
    seen = []
    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200 if request.headers["Authorization"] == "owner-secret" else 403)
    assert scan(tmp_path, handler, extra=("--base-url", "https://chosen.test/api"))[0] == 0
    assert seen == ["https://chosen.test/api/objects/object-1"] * 2


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf"])
def test_invalid_rate_rejected_by_cli(value):
    with pytest.raises(SystemExit):
        ledgerprobe.arguments(["--spec", "a", "--rules", "b", "--max-rps", value])


def test_no_rules_means_no_requests(tmp_path):
    empty = tmp_path / "empty.yaml"
    empty.write_text("[]")
    args = ledgerprobe.arguments(["--spec", "missing", "--rules", str(empty)])
    with pytest.raises(ValueError, match="at least one"):
        asyncio.run(ledgerprobe.execute(args))


def test_errors_do_not_print_secret_configuration(tmp_path, capsys):
    inputs = tmp_path / "bad.json"
    inputs.write_text('{"token":"sensitive",broken}')
    rules = tmp_path / "rule.json"
    rules.write_text(json.dumps(RULE))
    assert ledgerprobe.main(["--spec", "missing", "--rules", str(rules), "--inputs", str(inputs)]) == 2
    assert "sensitive" not in capsys.readouterr().err


@pytest.mark.parametrize("strict,exit_code", [(False, 0), (True, 1)])
def test_inconclusive_exit_policy_and_report_mapping(tmp_path, strict, exit_code):
    selected = {key: value for key, value in RULE.items() if key != "assertions"}
    selected["leak_detection"] = {}
    def handler(request):
        if request.headers.get("X-Actor") == "owner":
            return httpx.Response(200, json={"id": "object-a", "label": "owner-marker"})
        if request.headers.get("X-Actor") == "other":
            if request.url.path != "/objects/object-a":
                return httpx.Response(404, json={"error": "absent"})
            return httpx.Response(200, json={"result": "generic"})
        return httpx.Response(401)
    inputs = {"contexts": {"owner": {"X-Actor": "owner"}, "other": {"X-Actor": "other"}},
              "variables": {"id": "object-a"}}
    code, sarif, junit = scan(tmp_path, handler, rule=selected, inputs=inputs,
                              extra=("--fail-on-inconclusive",) if strict else ())
    assert code == exit_code
    assert junit.getroot().get("skipped") == "1"
    assert not junit.findall(".//failure")
    assert len(junit.findall(".//skipped")) == 1
    note = sarif["runs"][0]["results"][0]
    assert note["level"] == "note" and note["kind"] == "review"
    assert note["properties"]["reason"] == "ambiguous_2xx"
    assert "security-severity" not in json.dumps(sarif)
    assert "object-a" not in json.dumps(sarif)


def test_errors_keep_exit_two_even_with_fail_on_inconclusive(tmp_path):
    selected = {key: value for key, value in RULE.items() if key != "assertions"}
    selected["leak_detection"] = {}
    assert scan(tmp_path, lambda request: httpx.Response(500), rule=selected,
                extra=("--fail-on-inconclusive",))[0] == 2
