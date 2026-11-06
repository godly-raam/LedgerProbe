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
from pkg.integrations import ticket_body
from pkg.observability import github_summary, log_event, metrics_text
from pkg.results import build_document, write_document
from tests.test_cli import SPEC, scan
from tests.test_corpus import execute_profile

RULE = yaml.safe_load(Path("tests/fixtures/authz_server/rules_bfla_mutating.yaml").read_text())
INPUTS = json.loads(Path("tests/fixtures/authz_server/inputs.json").read_text())
SPEC_BFLA = {**SPEC, "paths": {
    "/api/v1/admin/action": {"post": {"responses": {"200": {"description": "ok"}}}},
    "/api/v1/admin/state": {"get": {"responses": {"200": {"description": "ok"}}}},
}}
SENTINELS = ("admin-canary-7391528-B", "LP-SENTINEL-7391528-B",
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
