"""Offline traffic import, templating, drift, privacy and plan-mode tests."""
from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import yaml

import ledgerprobe
from pkg.guardrails import GuardedClient
from pkg.integrations import (JiraTracker, LinearTracker, fingerprint_label,
                              load_integrations, process_tickets, target_slug)
from pkg.rules import load_rules
from pkg.traffic import (drift_report, import_har, import_postman, load_traffic_inventory,
                         write_import)
from tests.fixtures.authz_server import SPEC_PATH, create_app


def entry(request: httpx.Request, response: httpx.Response) -> dict:
    body = request.content.decode("utf-8") if request.content else ""
    return {
        "request": {
            "method": request.method,
            "url": str(request.url),
            "headers": [{"name": key, "value": value} for key, value in request.headers.items()],
            "queryString": [{"name": key, "value": value} for key, value in request.url.params.items()],
            **(({"postData": {"mimeType": request.headers.get("content-type", "application/json"),
                              "text": body}}) if body else {}),
        },
        "response": {
            "status": response.status_code,
            "headers": [{"name": key, "value": value} for key, value in response.headers.items()],
            "content": {"mimeType": response.headers.get("content-type", "application/json").split(";")[0],
                        "text": response.text},
        },
    }


async def recorded_har(profile: str = "bola_plain_fixed") -> dict:
    app = create_app(profile=profile)
    entries = []
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://authz.test") as client:
        for role, path in (("owner", "/api/v1/objects/obj-owner-1"),
                           ("other", "/api/v1/objects/obj-other-1")):
            response = await client.get(path, headers={"X-Actor": role,
                                                       "Authorization": f"Bearer {role}-capture-token"})
            entries.append(entry(response.request, response))
    return {"log": {"version": "1.2", "creator": {"name": "test", "version": "1"},
                    "entries": entries}}


def har_response(path: str, *, method: str = "GET", status: int = 200,
                 body: dict | None = None, query: str = "") -> dict:
    return {
        "request": {
            "method": method, "url": "https://api.example.test" + path + query,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
        },
        "response": {
            "status": status,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {"mimeType": "application/json", "text": json.dumps(body or {})},
        },
    }


def write_har(tmp_path: Path, name: str, entries: list[dict]) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps({"log": {"version": "1.2", "entries": entries}}))
    return path


def test_templating_matrix_and_normalization(tmp_path: Path):
    entries = [
        har_response("/api/v1/users/550e8400-e29b-41d4-a716-446655440000"),
        har_response("/api/v1/users/123"),
        har_response("/api/v1/objects/507f1f77bcf86cd799439011"),
        har_response("/api/v1/keys/abcdef0123456789abcdef0123456789"),
        har_response("/api/v1/blobs/AbCdEf0123456789_-xyz"),
        har_response("/api/v1/accounts/alice"),
        har_response("/api/v1/accounts/bob"),
        har_response("/api/v1/solo/carol"),
        har_response("/api/v1/health"),
        har_response("/api/v1/items/", query="?b=2&a=1"),
        har_response("/api/v1/items", query="?a=3&b=4"),
        har_response("/api/v1/v2/items"),
    ]
    har = write_har(tmp_path, "matrix.har", entries)
    result = import_har({"owner": har}, ["api.example.test"])
    endpoints = {(e["method"], e["path"]): e for e in result.inventory["endpoints"]}
    expected = {
        ("GET", "/api/v1/users/{id}"): "high",
        ("GET", "/api/v1/objects/{id}"): "high",
        ("GET", "/api/v1/keys/{id}"): "high",
        ("GET", "/api/v1/blobs/{id}"): "high",
        ("GET", "/api/v1/accounts/{id}"): "medium",
        ("GET", "/api/v1/solo/carol"): "low",
        ("GET", "/api/v1/health"): "low",
        ("GET", "/api/v1/items"): "high",
        ("GET", "/api/v1/v2/items"): "low",
    }
    for key, confidence in expected.items():
        assert key in endpoints, (key, sorted(endpoints))
        assert endpoints[key]["template_confidence"] == confidence
    items = endpoints[("GET", "/api/v1/items")]
    assert {p["name"] for p in items["parameters"] if p["in"] == "query"} == {"a", "b"}
    assert len([key for key in endpoints if key == ("GET", "/api/v1/items")]) == 1
    assert "single_observation_literal" in endpoints[("GET", "/api/v1/solo/carol")]["warnings"]


def test_postman_keeps_paths_methods_query_and_body_keys_only(tmp_path: Path):
    collection = {
        "info": {"name": "x", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "variable": [{"key": "token", "value": "SECRET_VARIABLE"}],
        "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "SECRET_AUTH"}]},
        "item": [{"name": "x", "request": {
            "method": "POST", "url": "https://api.example.test/api/v1/orders?expand=SECRET_QUERY",
            "header": [{"key": "Content-Type", "value": "application/json"}],
            "body": {"mode": "raw", "raw": json.dumps({"customer": {"email": "victim@example.test"},
                                                          "card": "4111111111111111"})},
        }, "response": [{"code": 201, "header": [{"key": "Content-Type", "value": "application/json"}],
                         "body": json.dumps({"token": "SECRET_RESPONSE", "id": "order-1"})}]}],
    }
    path = tmp_path / "collection.json"
    path.write_text(json.dumps(collection))
    result = import_postman({"owner": path}, ["api.example.test"])
    endpoint = result.inventory["endpoints"][0]
    assert endpoint["path"] == "/api/v1/orders"
    assert endpoint["method"] == "POST"
    assert {p["name"] for p in endpoint["parameters"] if p["in"] == "query"} == {"expand"}
    schema_text = json.dumps(result.inventory)
    assert "SECRET_VARIABLE" not in schema_text and "SECRET_AUTH" not in schema_text
    assert "victim@example.test" not in schema_text and "4111111111111111" not in schema_text
    assert "customer" in schema_text and "card" in schema_text
    assert any(rule.get("disabled") and rule.get("mutating") for rule in result.rules)


def test_graphql_operations_are_recorded_without_generated_rules(tmp_path: Path):
    entry = {
        "request": {"method": "POST", "url": "https://api.example.test/graphql",
                    "headers": [{"name": "Content-Type", "value": "application/json"}],
                    "postData": {"mimeType": "application/json",
                                 "text": json.dumps({"query": "mutation UpdateUser($id: ID!) { update }"})}},
        "response": {"status": 200, "headers": [{"name": "Content-Type", "value": "application/json"}],
                     "content": {"mimeType": "application/json", "text": "{\"ok\":true}"}},
    }
    har = write_har(tmp_path, "graphql.har", [entry])
    result = import_har({"owner": har, "other": har}, ["api.example.test"])
    endpoint = result.inventory["endpoints"][0]
    assert endpoint["graphql_operations"] == [{"name": "UpdateUser", "type": "mutation"}]
    assert result.inventory["graphql_operations"][0]["type"] == "mutation"
    assert result.rules == []


def test_privacy_scan_of_every_generated_artifact(tmp_path: Path, capsys):
    secrets = ["FAKE_BEARER_TOKEN_SHOULD_NOT_LEAK", "FAKE_COOKIE_VALUE_SHOULD_NOT_LEAK",
               "victim@example.test", "4111111111111111",
               "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ2aWN0aW0ifQ.signature"]
    body = {"id": "obj-owner-1", "email": secrets[2], "card": secrets[3],
            "access_token": secrets[0], "cookie": secrets[1], "jwt": secrets[4]}
    entries = [{
        "request": {"method": "GET", "url": "https://api.example.test/api/v1/users/550e8400-e29b-41d4-a716-446655440000?email=" + secrets[2],
                    "headers": [{"name": "Authorization", "value": "Bearer " + secrets[0]},
                                {"name": "Cookie", "value": "session=" + secrets[1]}],
                    "queryString": [{"name": "email", "value": secrets[2]}]},
        "response": {"status": 200, "headers": [{"name": "Content-Type", "value": "application/json"}],
                     "content": {"mimeType": "application/json", "text": json.dumps(body)}},
    }]
    har = write_har(tmp_path, "privacy.har", entries)
    result = import_har({"owner": har}, ["api.example.test"])
    paths = write_import(result, tmp_path / "out", allow_tracked_output=True)
    printed = capsys.readouterr()
    for path in paths:
        content = path.read_text()
        if path.name == "inputs.generated.json":
            continue
        for secret in secrets:
            assert secret not in content, (path, secret)
    for secret in secrets:
        assert secret not in printed.out and secret not in printed.err
    inputs = (tmp_path / "out" / "inputs.generated.json").read_text()
    for secret in secrets:
        assert secret not in inputs
    assert "550e8400-e29b-41d4-a716-446655440000" in inputs


def test_gitignore_guard_requires_explicit_override(tmp_path: Path):
    har = write_har(tmp_path, "x.har", [har_response("/api/v1/users/1")])
    result = import_har({"owner": har}, ["api.example.test"])
    with pytest.raises(ValueError, match="not git-ignored"):
        write_import(result, tmp_path / "tracked")
    paths = write_import(result, tmp_path / "ignored", allow_tracked_output=True)
    assert any(path.name == "inputs.generated.json" for path in paths)


def test_generated_results_redact_capture_values(tmp_path: Path, capsys):
    secret = "FAKE_RESULT_SECRET_SHOULD_NOT_LEAK"
    body = {"id": "obj-owner-1", "email": "victim@example.test",
            "card": "4111111111111111", "access_token": secret}
    entries = [
        {"request": {"method": "GET", "url": "https://api.example.test/api/v1/objects/550e8400-e29b-41d4-a716-446655440000",
                     "headers": [{"name": "Authorization", "value": "Bearer " + secret}]},
         "response": {"status": 200, "headers": [{"name": "Content-Type", "value": "application/json"}],
                      "content": {"mimeType": "application/json", "text": json.dumps(body)}}},
        {"request": {"method": "GET", "url": "https://api.example.test/api/v1/objects/550e8400-e29b-41d4-a716-446655440001",
                     "headers": [{"name": "Authorization", "value": "Bearer " + secret}]},
         "response": {"status": 200, "headers": [{"name": "Content-Type", "value": "application/json"}],
                      "content": {"mimeType": "application/json", "text": json.dumps(body)}}},
    ]
    har = write_har(tmp_path, "results.har", entries)
    imported = import_har({"owner": har, "other": har}, ["api.example.test"])
    out = tmp_path / "result-artifacts"
    write_import(imported, out, allow_tracked_output=True)
    args = ledgerprobe.arguments([
        "--spec", str(SPEC_PATH), "--base-url", "https://api.example.test",
        "--rules", str(out / "rules.generated.yaml"), "--inputs", str(out / "inputs.generated.json"),
        "--accept-generated", "--read-only", "--spec-check", "warn", "--tickets", "off",
        "--json", str(tmp_path / "privacy-results.json"), "--sarif", str(tmp_path / "privacy.sarif"),
    ])
    def handler(request):
        return httpx.Response(200, json=body)
    def client_factory(**kwargs):
        kwargs["max_rps"] = 10000
        kwargs["transport"] = httpx.MockTransport(handler)
        return GuardedClient(**kwargs)
    with patch.object(ledgerprobe, "GuardedClient", side_effect=client_factory):
        asyncio.run(ledgerprobe.execute(args))
    printed = capsys.readouterr()
    results = (tmp_path / "privacy-results.json").read_text()
    for value in (secret, "victim@example.test", "4111111111111111"):
        assert value not in results
        assert value not in printed.out and value not in printed.err


def test_generated_review_required_and_disabled_rules_are_not_executed(tmp_path: Path):
    har = write_har(tmp_path, "rules.har", [har_response("/api/v1/users/1")])
    result = import_har({"owner": har, "other": har}, ["api.example.test"])
    write_import(result, tmp_path / "out", allow_tracked_output=True)
    rules = tmp_path / "out" / "rules.generated.yaml"
    with pytest.raises(ValueError, match="accept-generated"):
        load_rules([rules])
    loaded = load_rules([rules], accept_generated=True)
    assert any(rule["review_required"] for rule in loaded)


async def run_generated(profile: str, tmp_path: Path) -> tuple[int, dict]:
    har = await recorded_har("bola_plain_fixed")
    har_path = write_har(tmp_path, "e2e.har", har["log"]["entries"])
    result = import_har({"owner": har_path, "other": har_path}, ["authz.test"])
    out = tmp_path / "generated"
    write_import(result, out, allow_tracked_output=True)
    inputs = json.loads((out / "inputs.generated.json").read_text())
    inputs["contexts"]["owner"]["X-Actor"] = "owner"
    inputs["contexts"]["other"]["X-Actor"] = "other"
    inputs_path = tmp_path / "inputs.json"
    inputs_path.write_text(json.dumps(inputs))
    json_path = tmp_path / (profile + ".json")
    args = ledgerprobe.arguments([
        "--spec", str(SPEC_PATH), "--base-url", "http://authz.test",
        "--rules", str(out / "rules.generated.yaml"), "--inputs", str(inputs_path),
        "--accept-generated", "--read-only", "--spec-check", "warn",
        "--sarif", str(tmp_path / (profile + ".sarif")), "--json", str(json_path),
        "--tickets", "off",
    ])
    def client_factory(**kwargs):
        kwargs["max_rps"] = 10000
        kwargs["transport"] = httpx.ASGITransport(app=create_app(profile=profile))
        return GuardedClient(**kwargs)
    with patch.object(ledgerprobe, "GuardedClient", side_effect=client_factory):
        code = await ledgerprobe.execute(args)
    document = json.loads(json_path.read_text())
    return code, document


def test_end_to_end_generated_rule_fails_vulnerable_and_passes_fixed(tmp_path: Path):
    vulnerable_code, vulnerable = asyncio.run(run_generated("bola_plain", tmp_path))
    assert vulnerable_code == 1, vulnerable
    assert vulnerable["summary"]["findings"] == 1
    fixed_code, fixed = asyncio.run(run_generated("bola_plain_fixed", tmp_path))
    assert fixed_code == 0, fixed
    assert fixed["summary"]["findings"] == 0


def test_drift_lists_and_fail_on_drift_exit_codes(tmp_path: Path):
    inventory = {"endpoints": [
        {"method": "GET", "path": "/api/v1/objects/{id}",
         "parameters": [{"name": "id", "in": "path"}, {"name": "expand", "in": "query"}]},
        {"method": "GET", "path": "/api/v1/traffic-only", "parameters": []},
    ]}
    spec = {
        "openapi": "3.0.3", "info": {"title": "x", "version": "1"},
        "paths": {
            "/api/v1/objects/{id}": {"get": {
                    "parameters": [{"name": "id", "in": "path", "required": True,
                                "schema": {"type": "string"}}],
                "responses": {"200": {"description": "ok"}},
            }},
            "/api/v1/not-seen": {"get": {"responses": {"200": {"description": "ok"}}}},
        },
    }
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(spec))
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(json.dumps(inventory))
    report = drift_report(load_traffic_inventory(inventory_path), load_traffic_inventory(inventory_path))
    assert report["counts"]["undocumented"] == 0
    assert ledgerprobe.main(["drift", "--spec", str(spec_path), "--inventory", str(inventory_path)]) == 0
    assert ledgerprobe.main(["drift", "--spec", str(spec_path), "--inventory", str(inventory_path),
                             "--fail-on-drift"]) == 1


def test_spec_check_warn_accepts_traffic_inventory_route(tmp_path: Path):
    inventory = {"endpoints": [{"method": "GET", "path": "/api/v1/not-in-spec/{id}",
                                 "parameters": [{"name": "id", "in": "path"}],
                                 "traffic_only": True}]}
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(json.dumps(inventory))
    rule = Path("tests/fixtures/authz_server/rules_missing.yaml")
    inputs = Path("tests/fixtures/authz_server/inputs.json")
    args = ledgerprobe.arguments(["--spec", str(SPEC_PATH), "--base-url", "http://authz.test",
                                  "--rules", str(rule), "--inputs", str(inputs),
                                  "--spec-check", "warn", "--inventory", str(inventory_path),
                                  "--read-only", "--tickets", "off",
                                  "--sarif", str(tmp_path / "x.sarif")])
    def client_factory(**kwargs):
        kwargs["max_rps"] = 10000
        kwargs["transport"] = httpx.ASGITransport(app=create_app(profile="endpoint_not_in_spec_warn"))
        return GuardedClient(**kwargs)
    with patch.object(ledgerprobe, "GuardedClient", side_effect=client_factory):
        assert asyncio.run(ledgerprobe.execute(args)) == 0


def config(tmp_path: Path, provider: str = "jira") -> object:
    tracker = {"provider": provider, "target_label": "staging", "token_env": "LP_TOKEN",
               "labels": ["security"], "max_new_tickets_per_run": 20, "max_api_calls": 100,
               "comment_cooldown_days": 7, "auto_close": False}
    if provider == "jira":
        tracker.update({"base_url": "https://jira.test", "project": "SEC"})
    else:
        tracker.update({"endpoint": "https://linear.test/graphql", "team_id": "team-1",
                        "state_open_id": "open", "state_resolved_id": "done"})
    path = tmp_path / "integrations.yaml"
    path.write_text(yaml.safe_dump({"schema_version": "ledgerprobe-integrations/1",
                                    "tracker": tracker, "slack": {}}))
    return load_integrations(path)


def finding() -> dict:
    from pkg.fingerprints import fingerprint
    fp = fingerprint(rule_id="r", method="GET", path_template="/objects/{id}",
                     identity_roles=["other", "owner"], check_type="bola")
    return {"fingerprint": fp, "rule_id": "r", "name": "n", "severity": "high", "owasp_category": "API1:2023",
            "cvss_score": 8.1, "path": "/objects/{id}", "path_template": "/objects/{id}",
            "method": "GET", "check_type": "bola", "identity_roles": ["other", "owner"],
            "verdict": "FAIL", "status": "failed", "confidence": "high", "reason": "leak_detected",
            "evidence": {"confirm_runs": 2, "overlap_count": 3}}


def test_plan_jira_is_get_only(monkeypatch, tmp_path):
    monkeypatch.setenv("LP_TOKEN", "token")
    seen = []
    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"issues": []})
    tracker = JiraTracker(config(tmp_path).tracker, "token", transport=httpx.MockTransport(handler))
    run = asyncio.run(process_tickets([finding()], config=config(tmp_path), target="staging",
                                      mode="plan", tracker=tracker))
    assert run.counts["new"] == 1 and run.actions[0]["kind"] == "create"
    assert {request.method for request in seen} == {"GET"}


def test_plan_linear_uses_query_not_mutation(monkeypatch, tmp_path):
    monkeypatch.setenv("LP_TOKEN", "token")
    seen = []
    def handler(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"data": {"issues": {"nodes": []}}})
    tracker = LinearTracker(config(tmp_path, "linear").tracker, "token",
                            transport=httpx.MockTransport(handler))
    run = asyncio.run(process_tickets([finding()], config=config(tmp_path, "linear"),
                                      target="staging", mode="plan", tracker=tracker))
    assert run.counts["new"] == 1
    assert seen and all("mutation" not in body["query"] for body in seen)


def test_plan_existing_ticket_plans_comment_and_reopen_without_writes(monkeypatch, tmp_path):
    monkeypatch.setenv("LP_TOKEN", "token")
    fp = finding()["fingerprint"]
    def issue(state: str) -> dict:
        return {"key": "SEC-1", "self": "https://jira.test/browse/SEC-1", "fields": {
            "summary": "existing", "status": {"name": state},
            "labels": [fingerprint_label(fp), target_slug("staging"), "security"],
            "description": "", "created": "2026-11-03T12:00:00Z",
            "comment": {"comments": []},
        }}
    for state, payload, expected in (("Open", {**finding(), "status": "passed", "verdict": "PASS"}, "comment"),
                                     ("Done", finding(), "reopen")):
        seen = []
        def handler(request):
            seen.append(request)
            return httpx.Response(200, json={"issues": [issue(state)]})
        tracker = JiraTracker(config(tmp_path).tracker, "token", transport=httpx.MockTransport(handler))
        run = asyncio.run(process_tickets([payload], config=config(tmp_path), target="staging",
                                          mode="plan", tracker=tracker))
        assert expected in {action["kind"] for action in run.actions}
        assert {request.method for request in seen} == {"GET"}