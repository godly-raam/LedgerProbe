import asyncio
import json
from pathlib import Path
from unittest.mock import patch
from unittest.mock import AsyncMock
from xml.etree import ElementTree as ET

import httpx
import pytest
import jsonschema

import ledgerprobe
from pkg.guardrails import GuardedClient
from pkg.fingerprints import fingerprint
from pkg.integrations import TicketRun


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
    rule = {**RULE, "target_endpoints": [{"path": "/objects", "method": "POST"}],
            "mutating": True,
            "verify": {"mode": "marker", "readback": {"method": "GET", "path": "/objects/{{id}}"}},
            "restore": [{"method": "POST", "path": "/objects"}]}
    rule.pop("assertions")
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
    assert "security-severity" not in json.dumps(note)
    assert "object-a" not in json.dumps(sarif)


def test_errors_keep_exit_two_even_with_fail_on_inconclusive(tmp_path):
    selected = {key: value for key, value in RULE.items() if key != "assertions"}
    selected["leak_detection"] = {}
    assert scan(tmp_path, lambda request: httpx.Response(500), rule=selected,
                extra=("--fail-on-inconclusive",))[0] == 2


def test_suppression_is_reported_and_excluded_from_exit(tmp_path):
    fp = fingerprint(rule_id=RULE["id"], method="GET", path_template="/objects/{id}",
                     identity_roles=["other", "owner"], check_type="bola")
    suppressions = tmp_path / "suppressions.yaml"
    suppressions.write_text(
        "- fingerprint: " + fp + "\n"
        "  reason: Accepted temporary test exception\n"
        "  owner: security-team\n"
        "  created: 2026-11-01\n"
        "  expires: 2026-12-01\n"
        "  ticket: SEC-1\n"
        "  approved_by: security-lead\n"
    )
    code, sarif, junit = scan(
        tmp_path, lambda request: httpx.Response(200, json={"id": "object-1"}),
        extra=("--suppressions", str(suppressions), "--json", str(tmp_path / "results.json")),
    )
    assert code == 0
    finding = sarif["runs"][0]["results"][0]
    assert finding["suppressions"][0]["kind"] == "external"
    assert junit.getroot().get("skipped") == "1"
    document = json.loads((tmp_path / "results.json").read_text())
    assert document["findings"][0]["status"] == "suppressed"
    assert document["findings"][0]["suppression"]["owner"] == "security-team"
    schema = json.loads((Path(__file__).parents[1] / "schemas" / "results.schema.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(document)


def test_baseline_new_vs_unchanged_exit_and_diff(tmp_path, capsys):
    fp = fingerprint(rule_id=RULE["id"], method="GET", path_template="/objects/{id}",
                     identity_roles=["other", "owner"], check_type="bola")
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"schema_version": "ledgerprobe-results/1",
                                    "findings": [{"fingerprint": fp, "rule_id": RULE["id"]}]}))
    handler = lambda request: httpx.Response(200, json={"id": "object-1"})
    assert scan(tmp_path, handler, extra=("--baseline", str(baseline), "--fail-on", "new"))[0] == 0
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"schema_version": "ledgerprobe-results/1", "findings": []}))
    assert scan(tmp_path, handler, extra=("--baseline", str(empty), "--fail-on", "new"))[0] == 1
    assert ledgerprobe.main(["diff", str(empty), str(baseline)]) == 0
    output = capsys.readouterr().out
    assert fp in output and RULE["id"] in output


def test_malformed_suppression_is_exit_two(tmp_path):
    for name, data in [("spec.json", SPEC), ("rules.json", RULE), ("inputs.json", {
        "contexts": {"owner": {"Authorization": "owner-secret"},
                     "other": {"Authorization": "other-secret"}},
        "variables": {"id": "object-1"},
    })]:
        (tmp_path / name).write_text(json.dumps(data))
    bad = tmp_path / "bad-suppressions.yaml"
    bad.write_text("- fingerprint: not-a-fingerprint\n")

    def client(**kwargs):
        return GuardedClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"id": "object-1"})), **kwargs)

    with patch.object(ledgerprobe, "GuardedClient", side_effect=client):
        code = ledgerprobe.main([
            "--spec", str(tmp_path / "spec.json"), "--rules", str(tmp_path / "rules.json"),
            "--inputs", str(tmp_path / "inputs.json"), "--sarif", str(tmp_path / "x.sarif"),
            "--suppressions", str(bad), "--max-rps", "10000",
        ])
    assert code == 2


def test_tracker_error_exit_three_after_reports(tmp_path):
    integrations = tmp_path / "integrations.yaml"
    integrations.write_text(json.dumps({
        "schema_version": "ledgerprobe-integrations/1",
        "tracker": {"provider": "jira", "base_url": "https://jira.test",
                    "project": "SEC", "token_env": "LP_TOKEN",
                    "target_label": "test"},
    }))
    def handler(request):
        return httpx.Response(200, json={"id": "object-1"})
    with patch.object(ledgerprobe, "process_tickets",
                      new=AsyncMock(return_value=TicketRun(errors=["tracker request failed"]))):
        code, sarif, _ = scan(tmp_path, handler, extra=(
            "--integrations", str(integrations), "--fail-on-tracker-error"))
    assert code == 3
    assert (tmp_path / "results.sarif").exists()
    assert sarif["runs"][0]["results"]


def test_json_logs_keep_ticket_lifecycle_off_stdout(tmp_path, capsys):
    integrations = tmp_path / "integrations.yaml"
    integrations.write_text(json.dumps({
        "schema_version": "ledgerprobe-integrations/1",
        "tracker": {"provider": "jira", "base_url": "https://jira.test",
                    "project": "SEC", "token_env": "LP_TOKEN", "target_label": "test"},
    }))
    code, _, _ = scan(tmp_path, lambda request: httpx.Response(200, json={"id": "object-1"}),
                      extra=("--integrations", str(integrations), "--tickets", "dry-run",
                             "--log-format", "json"))
    assert code == 1
    lines = [line for line in capsys.readouterr().out.splitlines() if line]
    assert lines
    assert all(line.startswith("{") and json.loads(line) for line in lines)
