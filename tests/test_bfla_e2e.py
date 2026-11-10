from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path

import httpx
import jsonschema
import pytest
import yaml

from pkg.dojo import write_export
from pkg.fingerprints import fingerprint
from pkg.guardrails import GuardedClient
from pkg.integrations import FakeTracker, ticket_body
from pkg.observability import github_summary, log_event, metrics_text
from pkg.results import build_document, write_document
from pkg.rules import load_rules, run_rules
from tests.test_cli import SPEC, scan
from tests.test_corpus import execute_profile
from tests.test_integrations import NOW, config as integration_config, run as run_tickets

RULE = yaml.safe_load(Path("tests/fixtures/authz_server/rules_bfla_mutating.yaml").read_text())
INPUTS = json.loads(Path("tests/fixtures/authz_server/inputs.json").read_text())
SPEC_BFLA = {**SPEC, "paths": {
    "/api/v1/admin/action": {"post": {"responses": {"200": {"description": "ok"}}}},
    "/api/v1/admin/state": {"get": {"responses": {"200": {"description": "ok"}}}},
}}
SENTINELS = ("admin-canary-7391528-B", "LP-SENTINEL-" + "7391528-C",
             "token-admin", "token-user")


def no_http(request):
    pytest.fail("blocked BFLA mutation contacted target")


@pytest.mark.parametrize("extra,name", [
    (("--allow-host", "target.test"), "test_bfla_gate_without_allow_mutations"),
    (("--allow-mutations",), "test_bfla_gate_non_allowlisted_host"),
    (("--environment", "production", "--read-only", "--allow-production-read-only",
      "--allow-mutations", "--allow-host", "target.test"), "test_bfla_gate_production"),
    (("--read-only", "--allow-mutations", "--allow-host", "target.test"), "test_bfla_gate_read_only"),
])
def test_bfla_mutation_gates(tmp_path, extra, name):
    code, _, junit = scan(tmp_path, no_http, rule=RULE, spec=SPEC_BFLA, inputs=INPUTS, extra=extra)
    assert code == 2
    assert len(junit.findall(".//skipped")) == 1


def test_bfla_gate_kill_switch(tmp_path):
    marker = tmp_path / "STOP"
    marker.write_text("stop")
    code, _, junit = scan(tmp_path, no_http, rule=RULE, spec=SPEC_BFLA, inputs=INPUTS,
                          extra=("--kill-file", str(marker), "--allow-mutations",
                                 "--allow-host", "target.test"))
    assert code == 4
    assert len(junit.findall(".//skipped")) == 1


def _mutation_handler(fail):
    state = {"marker": "admin-default"}
    calls = []
    def handler(request):
        calls.append(request)
        if request.method == "GET" and request.url.path == "/api/v1/admin/state":
            return httpx.Response(200, json={"marker": state["marker"]})
        if request.url.path == "/api/v1/admin/action":
            token = request.headers["Authorization"]
            if token == "Bearer token-user" and fail:
                raise httpx.ConnectError("simulated transport error", request=request)
            body = json.loads(request.content)
            state["marker"] = body.get("marker") or "admin-default"
            return httpx.Response(200, json={"status": "accepted"})
        return httpx.Response(404)
    return handler, calls, state


def test_bfla_restore_runs_after_fail(tmp_path):
    handler, calls, state = _mutation_handler(False)
    code, _, junit = scan(tmp_path, handler, rule=RULE, spec=SPEC_BFLA, inputs=INPUTS,
                          extra=("--allow-mutations", "--allow-host", "target.test"))
    assert code == 1 and len(junit.findall(".//failure")) == 1
    actions = [r for r in calls if r.url.path == "/api/v1/admin/action"]
    assert len(actions) == 2
    assert actions[-1].headers["Authorization"] == "Bearer token-admin"
    assert state["marker"] == "admin-default"


def test_bfla_restore_runs_after_error(tmp_path):
    handler, calls, state = _mutation_handler(True)
    code, _, junit = scan(tmp_path, handler, rule=RULE, spec=SPEC_BFLA, inputs=INPUTS,
                          extra=("--allow-mutations", "--allow-host", "target.test"))
    assert code == 2 and len(junit.findall(".//error")) == 1
    assert [r.headers["Authorization"] for r in calls
            if r.url.path == "/api/v1/admin/action"] == ["Bearer token-user", "Bearer token-admin"]
    assert state["marker"] == "admin-default"


def test_bfla_fingerprints_and_schema_and_leaks(tmp_path):
    bfla = fingerprint(rule_id="r", method="GET", path_template="/admin", identity_roles=["admin", "user"],
                       check_type="bfla")
    same = fingerprint(rule_id="r", method="GET", path_template="/admin", identity_roles=["admin", "user"],
                       check_type="bfla")
    bola = fingerprint(rule_id="r", method="GET", path_template="/admin", identity_roles=["admin", "user"],
                       check_type="bola")
    assert bfla == same and bfla != bola
    assert bfla != fingerprint(rule_id="r", method="GET", path_template="/admin",
                               identity_roles=["admin", "auditor"], check_type="bfla")
    code, result, sarif_path, junit_path = asyncio.run(execute_profile("bfla_read_vulnerable", tmp_path))
    assert code == 1 and result["verdict"] == "FAIL"
    document = build_document([result], target="http://authz.test", modes={})
    schema = json.loads(Path("schemas/results.schema.json").read_text())
    jsonschema.validate(document, schema)
    json_path = tmp_path / "results.json"
    write_document(document, json_path)
    dojo_path = tmp_path / "defectdojo.json"
    write_export([result], dojo_path, target="http://authz.test")
    assert "285" in dojo_path.read_text()
    ticket = ticket_body(result, target="http://authz.test", fingerprint=result["fingerprint"], ci_url=None)
    stream = io.StringIO()
    log_event("run", "finding", target="http://authz.test", tool_version="1.1.0", result=result, stream=stream)
    metrics = metrics_text([result], duration_seconds=0)
    summary = github_summary(document)
    surfaces = [sarif_path.read_text(), junit_path.read_text(), json_path.read_text(),
                dojo_path.read_text(), ticket, stream.getvalue(), metrics, summary]
    assert all(sentinel not in text for sentinel in SENTINELS for text in surfaces)
    assert "CWE-285" in dojo_path.read_text() or "285" in dojo_path.read_text()


def test_bfla_fail_through_faketracker_create_and_comment(tmp_path):
    _, result, _, _ = asyncio.run(execute_profile("bfla_read_vulnerable", tmp_path))
    tracker = FakeTracker(now=NOW)
    cfg = integration_config(tmp_path)
    run_tickets([result], cfg, tracker, now=NOW)
    changed = {**result, "evidence": {**result.get("evidence", {}), "confirm_runs": 99}}
    run_tickets([changed], cfg, tracker, now=NOW + __import__("datetime").timedelta(days=1))
    assert len(tracker.tickets) == 1
    ticket = next(iter(tracker.tickets.values()))
    assert ticket.comments, "FakeTracker comment path was not exercised"
    surfaces = [ticket.title, ticket.description, " ".join(ticket.labels),
                " ".join(comment.body for comment in ticket.comments)]
    assert all(sentinel not in text for sentinel in SENTINELS for text in surfaces)


def _bfla_fingerprint(host, port, object_id, token, tmp_path):
    rule = load_rules([Path("tests/fixtures/authz_server/rules_bfla_read.yaml")])[0]
    rule = {**rule, "target_endpoints": [{"path": "/api/v1/objects/{id}", "method": "GET"}],
            "parameters": {"path": {"id": "{{id}}"}},
            "leak_detection": {"canaries": ["admin-canary-7391528-B"]}}
    inventory = {"base_url": f"https://{host}:{port}", "graph": [], "endpoints": [{
        "path": "/api/v1/objects/{id}", "method": "GET", "parameters": [
            {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
        "request_body": None, "operation_id": "getObject"}]}
    def handler(request):
        return httpx.Response(200, json={"id": object_id,
                                          "admin_canary": "admin-canary-7391528-B"})
    async def execute():
        async with GuardedClient(transport=httpx.MockTransport(handler)) as client:
            return await run_rules(inventory, [rule], client,
                                   contexts={"admin": {"Authorization": token},
                                             "user": {"Authorization": "user-" + token}},
                                   variables={"id": object_id})
    row = asyncio.run(execute())[0]
    assert row["check_type"] == "bfla"
    bola_rule = {key: value for key, value in rule.items() if key not in {"check", "privileged", "unprivileged"}}
    bola_rule["auth_contexts"] = {"primary": "admin", "forbidden": "user"}
    async def execute_bola():
        async with GuardedClient(transport=httpx.MockTransport(handler)) as client:
            return await run_rules(inventory, [bola_rule], client,
                                   contexts={"admin": {"Authorization": token},
                                             "user": {"Authorization": "user-" + token}},
                                   variables={"id": object_id})
    bola = asyncio.run(execute_bola())[0]
    assert row["fingerprint"] != bola["fingerprint"]
    document = build_document([row], target=inventory["base_url"], modes={})
    jsonschema.validate(document, json.loads(Path("schemas/results.schema.json").read_text()))
    return row["fingerprint"]


def test_bfla_fingerprint_is_stable_between_runs(tmp_path):
    values = [(host, port, object_id, token) for host, port, object_id, token in [
        ("alpha.test", 443, "obj-a", "token-a"), ("beta.test", 8443, "obj-b", "token-b")]]
    fingerprints = [_bfla_fingerprint(*value, tmp_path) for value in values]
    assert fingerprints[0] == fingerprints[1]
