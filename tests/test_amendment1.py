"""Regression tests for the post-first-run Amendment 1 engine changes."""
from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from urllib.parse import parse_qs
from xml.etree import ElementTree as ET

import httpx
import pytest
import yaml

import ledgerprobe
from benchmark.run import _junit_results
from pkg.auth import AuthError, AuthManager
from pkg.guardrails import GuardedClient
from pkg.parser import _resolve, parse_document
from pkg.reporter import write_junit
from pkg.rules import _MISSING, _Runtime, load_rules, run_rules
from pkg.rules.verdict import evaluate_scoped


def _spec(**paths):
    return {"openapi": "3.0.3", "info": {"title": "Generic", "version": "1"},
            "servers": [{"url": "https://generic.test"}], "paths": paths}


def _rule(**changes):
    value = {
        "id": "enum-role", "name": "Enum role injection", "severity": "HIGH",
        "owasp_category": "API3:2023", "cvss_score": 8.1,
        "target_endpoints": [{"path": "/account", "method": "PATCH"}],
        "auth_contexts": {"primary": "owner", "forbidden": "other"},
        "check": "mass_assignment", "mutating": True,
        "request": {"method": "PATCH", "path": "/account", "body": {}},
        "readback": {"request": {"method": "GET", "path": "/account"}, "paths": ["role"]},
        "inject": [{"name": "role", "type": "string"}],
        "restore": [{"method": "PATCH", "path": "/account", "body": {"role": "member"}}],
    }
    value.update(changes)
    return value


def _inventory(schema):
    return {"base_url": "https://generic.test", "graph": [], "endpoints": [{
        "path": "/account", "method": "PATCH", "operation_id": "patchAccount",
        "parameters": [], "response_fields": [], "security": [],
        "request_body": {"required": True, "content": {
            "application/json": {"schema": schema}}},
    }]}


def _mass_client(handler):
    return GuardedClient(max_rps=10000, transport=httpx.MockTransport(handler))


def test_refs_in_request_body_parameters_and_responses_resolve():
    document = _spec()
    document["components"] = {
        "schemas": {
            "Base": {"type": "object", "required": ["name"], "properties": {
                "id": {"type": "string", "readOnly": True},
                "name": {"type": "string"}}},
            "Update": {"allOf": [
                {"$ref": "#/components/schemas/Base"},
                {"type": "object", "required": ["role"], "properties": {
                    "role": {"type": "string", "enum": ["member", "admin"]}}}]},
            "Reply": {"type": "object", "properties": {
                "id": {"type": "string"}, "state": {"type": "string"}}},
        },
        "requestBodies": {"Update": {"required": True, "content": {
            "application/json": {"schema": {"$ref": "#/components/schemas/Update"}}}}},
        "parameters": {"AccountId": {"name": "id", "in": "path", "required": True,
                                     "schema": {"type": "string"}}},
        "responses": {"Reply": {"description": "OK", "content": {
            "application/json": {"schema": {"$ref": "#/components/schemas/Reply"}}}}},
    }
    document["paths"] = {
        "/accounts/{id}": {
            "parameters": [{"$ref": "#/components/parameters/AccountId"}],
            "patch": {"operationId": "patchAccount",
                      "requestBody": {"$ref": "#/components/requestBodies/Update"},
                      "responses": {"200": {"$ref": "#/components/responses/Reply"}}},
        }
    }
    inventory = parse_document(document)
    endpoint = inventory["endpoints"][0]
    schema = endpoint["request_body"]["content"]["application/json"]["schema"]
    assert schema["required"] == ["name", "role"]
    assert schema["properties"]["id"]["readOnly"] is True
    assert schema["properties"]["role"]["enum"] == ["member", "admin"]
    assert endpoint["parameters"][0]["schema"] == {"type": "string"}
    assert endpoint["response_fields"] == ["id", "state"]

    async def body():
        runtime = _Runtime(inventory, object(), {"owner": {}}, {"name": "Ada", "role": "admin"})
        return await runtime.body(schema, _MISSING, endpoint, {}, "owner", (), [0])

    assert asyncio.run(body()) == {"name": "Ada", "role": "admin"}


def test_composition_keywords_merge_and_keep_constraints():
    document = _spec()
    document["components"] = {"schemas": {
        "A": {"allOf": [{"type": "object", "properties": {"a": {"type": "string"}},
                         "required": ["a"]},
                        {"type": "object", "properties": {"b": {"type": "integer"}},
                         "required": ["b"]}]},
        "B": {"oneOf": [{"type": "object", "properties": {"c": {"type": "string"}}},
                        {"type": "object", "properties": {"d": {"type": "boolean"}}}]},
        "C": {"anyOf": [{"type": "object", "properties": {"e": {"type": "string"}}},
                        {"type": "object", "properties": {"f": {"type": "string"}}}]},
    }}
    resolved = _resolve(document, document)["components"]["schemas"]
    assert "allOf" not in resolved["A"] and resolved["A"]["required"] == ["a", "b"]
    assert set(resolved["A"]["properties"]) == {"a", "b"}
    assert "oneOf" not in resolved["B"] and set(resolved["B"]["properties"]) == {"c", "d"}
    assert "anyOf" not in resolved["C"] and set(resolved["C"]["properties"]) == {"e", "f"}


def test_unresolvable_ref_names_the_reference_without_a_traceback():
    document = _spec(**{"/x": {"post": {"requestBody": {
        "$ref": "#/components/requestBodies/MissingBody"}, "responses": {"200": {"description": "OK"}}}}})
    with pytest.raises(ValueError, match="MissingBody"):
        parse_document(document)


def test_circular_refs_terminate():
    document = _spec()
    document["components"] = {"schemas": {"Node": {
        "type": "object", "properties": {"next": {"$ref": "#/components/schemas/Node"}}}}}
    document["paths"] = {"/nodes": {"get": {"responses": {"200": {
        "description": "OK", "content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/Node"}}}}}}}}
    inventory = parse_document(document)
    assert inventory["endpoints"][0]["response_fields"] == ["next"]


def _auth_config(**params):
    base = {"method": "POST", "path": "/token", "token_json_path": "access_token"}
    base.update(params)
    return {"schema_version": "ledgerprobe-auth/1", "identities": {"owner": {
        "provider": "login_request", "environment": "lab", "params": base}}}


def test_form_login_posts_urlencoded_credentials_and_extracts_token(monkeypatch, caplog, tmp_path):
    sentinel = "FORM-PASSWORD-SENTINEL-7391528"
    monkeypatch.setenv("AUTH_TEST_PASSWORD", sentinel)
    seen = []

    def handler(request):
        seen.append(request)
        if request.url.path == "/token":
            assert request.headers["content-type"].startswith("application/x-www-form-urlencoded")
            assert parse_qs(request.content.decode()) == {
                "username": ["owner"], "password": [sentinel], "grant_type": ["password"]}
            return httpx.Response(200, json={"access_token": "TOKEN-1", "expires_in": 60})
        assert request.headers["authorization"] == "Bearer TOKEN-1"
        return httpx.Response(200, json={"ok": True})

    async def run():
        client = _mass_client(handler)
        config = _auth_config(body={"username": "owner", "password_ref": "env:AUTH_TEST_PASSWORD",
                                    "grant_type": "password"}, body_format="form")
        manager = AuthManager(config, {}, "https://generic.test", client)
        with caplog.at_level(logging.DEBUG):
            await manager.initialize()
        results = await run_rules(
            {"base_url": "https://generic.test", "graph": [], "endpoints": [{
                "path": "/me", "method": "GET", "operation_id": "me", "parameters": [],
                "request_body": None, "response_fields": [], "security": []}]},
            [{"id": "me", "name": "Me", "severity": "LOW", "owasp_category": "API1:2023",
              "cvss_score": 1.0, "target_endpoints": [{"path": "/me", "method": "GET"}],
              "auth_contexts": {"primary": "owner", "forbidden": "owner"},
              "assertions": [{"type": "status_code", "expected": 200}]}],
            client, contexts=manager.contexts, variables={})
        return results

    results = asyncio.run(run())
    assert results[0]["status"] == "passed"
    assert len(seen) == 3
    report = tmp_path / "junit.xml"
    write_junit(results, report)
    assert sentinel not in json.dumps(results)
    assert sentinel not in report.read_text(encoding="utf-8")
    assert sentinel not in caplog.text


def test_form_login_wrong_credentials_fail_fast_and_never_echo_password(monkeypatch):
    sentinel = "WRONG-FORM-PASSWORD-SENTINEL-7391528"
    monkeypatch.setenv("AUTH_TEST_PASSWORD", sentinel)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(401, json={"detail": "bad credentials"})

    config = _auth_config(body={"username": "owner", "password_ref": "env:AUTH_TEST_PASSWORD"},
                          body_format="form")

    async def run():
        client = _mass_client(handler)
        manager = AuthManager(config, {}, "https://generic.test", client)
        with pytest.raises(AuthError) as caught:
            await manager.initialize()
        return caught.value

    error = asyncio.run(run())
    assert error.reason == "auth_failed"
    assert len(calls) == 1
    assert sentinel not in str(error)
    assert sentinel not in repr(error)


def test_caller_scope_generic_overlap_is_inconclusive_without_a_canary():
    result = evaluate_scoped(
        scope="caller",
        baseline={"status": 200, "body": {"status": "ok", "currency": "USD",
                                          "fee": "1.00", "canary": "OWNER-CANARY"}},
        forbidden={"status": 200, "body": {"status": "ok", "currency": "USD",
                                           "fee": "1.00", "canary": "OTHER-CANARY"}},
        canaries=["OWNER-CANARY"], min_unique_leaf_values=3, confirm=0,
        require_owner_canary_in_baseline=True,
    )
    assert result["verdict"] == "INCONCLUSIVE"
    assert result["reason"] == "overlap_without_canary"
    assert result["evidence"]["canary_matched"] is False


def test_shared_caller_loader_requires_nonempty_canaries(tmp_path):
    for scope in ("caller", "shared"):
        rule = {"id": scope, "name": scope, "severity": "LOW", "owasp_category": "API1:2023",
                "cvss_score": 1.0, "target_endpoints": [{"path": "/x", "method": "GET"}],
                "auth_contexts": {"primary": "owner", "forbidden": "other"},
                "scope": scope, "leak_detection": {"canaries": []}}
        if scope == "caller":
            rule["require_owner_canary_in_baseline"] = True
        path = tmp_path / f"{scope}.yaml"
        path.write_text(yaml.safe_dump(rule), encoding="utf-8")
        with pytest.raises(ValueError, match="canaries"):
            load_rules([path])


def _enum_handler(mode, calls):
    state = {"role": "member"}

    def handler(request):
        if request.method == "GET":
            calls.append((request.method, request.url.path, None))
            return httpx.Response(200, json=dict(state))
        payload = json.loads(request.content or b"{}")
        role = payload.get("role")
        calls.append((request.method, request.url.path, role))
        if role == "member":
            state["role"] = "member"
            return httpx.Response(200, json={"ok": True})
        if mode == "vulnerable":
            state["role"] = role
            return httpx.Response(200, json={"ok": True})
        if mode == "allowlist":
            return httpx.Response(403, json={"error": "forbidden"})
        return httpx.Response(500, json={"error": "invalid enum"})

    return handler


def _run_mass(rule, schema, mode):
    calls = []

    async def run():
        client = _mass_client(_enum_handler(mode, calls))
        results = await run_rules(
            _inventory(schema),
            [rule], client,
            contexts={"owner": {"Authorization": "owner"}, "other": {"Authorization": "other"}},
            allow_mutations=True, allowed_hosts=("generic.test",), experimental=True,
        )
        return results[0]

    return asyncio.run(run()), calls


ENUM_SCHEMA = {"type": "object", "properties": {
    "role": {"type": "string", "enum": ["member", "admin", "superuser"]}}}


def test_mass_assignment_uses_enum_value_that_differs_from_before():
    result, calls = _run_mass(_rule(), ENUM_SCHEMA, "vulnerable")
    assert result["verdict"] == "FAIL"
    assert result["reason"] == "mass_assignment"
    assert result["evidence"]["fields"] == ["role"]
    assert [role for method, _path, role in calls if method == "PATCH"] == ["admin", "member"]
    assert result["evidence"]["mutation_status"] == 200


def test_mass_assignment_values_are_tried_in_order_and_stopped_at_max_attempts():
    rule = _rule(inject=[{"name": "role", "values": ["user", "admin"]}], max_attempts=2)
    result, calls = _run_mass(rule, ENUM_SCHEMA, "allowlist")
    assert result["verdict"] == "PASS"
    assert result["note"] == "rejected"
    assert [role for method, _path, role in calls if method == "PATCH"] == ["user", "member"]


def test_mass_assignment_enum_allowlist_is_pass_and_restores_each_attempt():
    result, calls = _run_mass(_rule(inject=[{"name": "role", "values": ["admin"]}]),
                              ENUM_SCHEMA, "allowlist")
    assert result["verdict"] == "PASS"
    assert [role for method, _path, role in calls if method == "PATCH"] == ["admin", "member"]
    assert result["evidence"]["fields_injected"] == 1


def test_mass_assignment_invalid_enum_is_inconclusive_without_echoing_value(tmp_path):
    sentinel = "INVALID-ENUM-SENTINEL-7391528"
    result, _ = _run_mass(_rule(inject=[{"name": "role", "values": [sentinel]}]),
                          ENUM_SCHEMA, "invalid")
    assert result["verdict"] == "INCONCLUSIVE"
    assert result["reason"] in {"server_error", "unexpected_status"}
    assert result["evidence"]["mutation_status"] == 500
    report = tmp_path / "junit.xml"
    write_junit([result], report)
    assert sentinel not in json.dumps(result)
    assert sentinel not in report.read_text(encoding="utf-8")


def test_mass_assignment_max_attempts_is_bounded():
    from pkg.rules import _validate_rules
    with pytest.raises(ValueError, match="max_attempts"):
        _validate_rules([_rule(max_attempts=4)], require_mutating=False, experimental=True)


@pytest.mark.parametrize("content,missing", [("[]", False), (None, True)])
def test_missing_or_empty_rules_file_is_a_clear_exit_two(tmp_path, capsys, content, missing):
    rules = tmp_path / ("missing.yaml" if missing else "empty.yaml")
    if content is not None:
        rules.write_text(content, encoding="utf-8")
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps(_spec(**{"/x": {"get": {"responses": {"200": {"description": "OK"}}}}})),
                    encoding="utf-8")
    code = ledgerprobe.main(["--spec", str(spec), "--rules", str(rules),
                             "--sarif", str(tmp_path / "out.sarif"), "--read-only"])
    captured = capsys.readouterr()
    assert code == 2
    assert "rules" in captured.err.lower()
    assert "Traceback" not in captured.err
    assert "rule" in captured.err.lower()


def test_every_junit_testcase_declares_its_verdict(tmp_path):
    rows = [
        {"rule_id": "p", "name": "Pass", "method": "GET", "path": "/p", "status": "passed"},
        {"rule_id": "f", "name": "Fail", "method": "GET", "path": "/f", "status": "failed",
         "verdict": "FAIL", "message": "failed"},
        {"rule_id": "i", "name": "Inconclusive", "method": "GET", "path": "/i",
         "status": "inconclusive", "verdict": "INCONCLUSIVE", "message": "unknown"},
        {"rule_id": "s", "name": "Skipped", "method": "GET", "path": "/s",
         "status": "skipped", "verdict": "SKIPPED", "message": "blocked"},
        {"rule_id": "e", "name": "Error", "method": "GET", "path": "/e",
         "status": "error", "verdict": "ERROR", "message": "error"},
    ]
    path = tmp_path / "junit.xml"
    write_junit(rows, path)
    cases = ET.parse(path).findall(".//testcase")
    verdicts = [case.find("./properties/property[@name='ledgerprobe.verdict']").get("value")
                for case in cases]
    assert verdicts == ["PASS", "FAIL", "INCONCLUSIVE", "SKIPPED", "ERROR"]


def test_benchmark_scorer_reads_verdict_property_and_never_infers_pass(tmp_path):
    path = tmp_path / "junit.xml"
    path.write_text(
        "<testsuite>"
        "<testcase classname='missing' name='missing'/>"
        "<testcase classname='explicit' name='explicit'><properties>"
        "<property name='ledgerprobe.verdict' value='INCONCLUSIVE'/>"
        "</properties></testcase>"
        "<testcase classname='pass' name='pass'><properties>"
        "<property name='ledgerprobe.verdict' value='PASS'/>"
        "</properties></testcase>"
        "</testsuite>", encoding="utf-8")
    results = _junit_results(path)
    assert results["missing"]["verdict"] == "MISSING"
    assert results["explicit"]["verdict"] == "INCONCLUSIVE"
    assert results["pass"]["verdict"] == "PASS"
