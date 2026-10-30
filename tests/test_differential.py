"""All differential traffic goes through the real GuardedClient with MockTransport."""
import asyncio
import json
import re
from time import monotonic
from uuid import UUID

import httpx
import pytest

from pkg.guardrails import GuardedClient
from pkg.rules import _nonexistent_value, load_rules, run_rules
from pkg.rules import _MISSING

OWNER = {"id": "object-a", "label": "owner-marker", "currency": "USD", "state": "active"}
CONTEXTS = {"owner": {"X-Actor": "owner"}, "other": {"X-Actor": "other"}}


def rule(**changes):
    result = {"id": "differential", "name": "Object isolation", "severity": "high", "cvss_score": 8.1,
              "owasp_category": "API1:2023", "target_endpoints": [{"path": "/objects/{id}", "method": "GET"}],
              "auth_contexts": {"primary": "owner", "forbidden": "other"}, "leak_detection": {}}
    result.update(changes)
    return result


def inventory(method="GET", schema=None):
    return {"base_url": "https://target.test", "graph": [], "endpoints": [
        {"path": "/objects/{id}", "method": method, "operation_id": "getObject", "request_body": None,
         "parameters": [{"name": "id", "in": "path", "required": True,
                         "schema": {"type": "string"} if schema is None else schema}]}]}


def scan(handler, selected=None, inv=None, variables=None, **client_options):
    requests = []
    def recording(request):
        requests.append(request)
        return handler(request)
    async def execute():
        async with GuardedClient(max_rps=10000, transport=httpx.MockTransport(recording), **client_options) as client:
            return (await run_rules(inv or inventory(), [selected or rule()], client, CONTEXTS,
                                    {"id": "object-a"} if variables is None else variables))[0]
    return asyncio.run(execute()), requests


def scenario_handler(case):
    forbidden_runs = 0
    def handler(request):
        nonlocal forbidden_runs
        actor = request.headers.get("X-Actor")
        if actor == "owner":
            return httpx.Response(403 if case == "baseline" else 200, json=OWNER)
        if not actor:
            return httpx.Response(200 if case == "public" else 401,
                                  json=OWNER if case == "public" else {"error": "auth required"})
        if request.url.path != "/objects/object-a":
            if case in {"cached", "static"}:
                return httpx.Response(200, json=OWNER if case == "cached" else {"currency": "USD"})
            return httpx.Response(404, json={"error": "absent"})
        forbidden_runs += 1
        if case == "timeout":
            raise httpx.ReadTimeout("synthetic failure", request=request)
        if case == "unstable" and forbidden_runs > 1:
            return httpx.Response(403)
        status = {"403": 403, "404": 404, "500": 500, "429": 429}.get(case, 200)
        body = {"currency": "USD"} if case == "static" else {"error": "forbidden"} if case == "soft" else OWNER
        return httpx.Response(status, json=body, headers={"Retry-After": "0.01"} if status == 429 else {})
    return handler


@pytest.mark.parametrize("case,verdict,reason,note", [
    ("bola", "FAIL", "leak_detected", None), ("403", "PASS", None, None),
    ("404", "PASS", None, None), ("soft", "PASS", None, "soft_deny"),
    ("static", "PASS", None, "soft_deny"), ("public", "PASS", None, "public_endpoint"),
    ("500", "INCONCLUSIVE", "server_error", None), ("429", "INCONCLUSIVE", "rate_limited", None),
    ("timeout", "INCONCLUSIVE", "timeout", None), ("unstable", "INCONCLUSIVE", "not_reproducible", None),
    ("cached", "INCONCLUSIVE", "invalid_control", None), ("baseline", "ERROR", "baseline_not_2xx", None),
])
def test_transport_scenarios(case, verdict, reason, note):
    result, requests = scan(scenario_handler(case), read_only=True)
    assert result["verdict"] == verdict
    assert result.get("reason") == reason
    assert result.get("note") == note
    assert all(request.method == "GET" for request in requests)
    assert "object-a" not in json.dumps(result)
    assert "owner-marker" not in json.dumps(result)
    if case == "bola":
        assert result["evidence"]["confirm_runs"] == 2
        assert len(requests) == 6  # baseline, forbidden, two controls, two confirms
    if case in {"403", "404", "500", "429", "timeout"}:
        assert len(requests) == 2
    if case == "baseline":
        assert len(requests) == 1


def test_canary_leak_and_ignored_fields():
    selected = rule(leak_detection={"canaries": ["{{canary_value}}"], "min_unique_leaf_values": 99})
    result, _ = scan(scenario_handler("bola"), selected, variables={"id": "object-a", "canary_value": "owner-marker"})
    assert (result["verdict"], result["reason"]) == ("FAIL", "leak_detected")
    selected["leak_detection"]["ignore_fields"] = ["label"]
    result, _ = scan(scenario_handler("bola"), selected, variables={"id": "object-a", "canary_value": "owner-marker"})
    assert result["verdict"] != "FAIL"


def test_unknown_id_schema_skips_control_and_reduces_confidence():
    result, requests = scan(scenario_handler("bola"), inv=inventory(schema={}))
    assert result["verdict"] == "INCONCLUSIVE"
    assert result["confidence"] == "reduced"
    assert result["evidence"]["nonexistent_skipped"] is True
    assert all(r.url.path == "/objects/object-a" for r in requests)


def test_public_control_has_no_context_headers_or_inherited_cookies():
    seen = []
    def handler(request):
        seen.append(request)
        response = scenario_handler("bola")(request)
        response.headers["Set-Cookie"] = "session=synthetic; Path=/"
        return response
    result, requests = scan(handler)
    anonymous = [request for request in requests if "X-Actor" not in request.headers]
    assert len(anonymous) == 1
    assert anonymous[0].headers.get("cookie") == ""
    assert "authorization" not in anonymous[0].headers
    assert result["verdict"] == "FAIL"


def test_legacy_status_rule_preserves_404_failure():
    selected = rule()
    selected.pop("leak_detection")
    selected["assertions"] = [{"type": "status_code", "expected": 403}]
    result, requests = scan(scenario_handler("404"), selected)
    assert (result["status"], result["reason"]) == ("failed", "assertion_failed")
    assert len(requests) == 2


@pytest.mark.parametrize("changes", [
    {"leak_detection": {"unknown": True}}, {"leak_detection": {"canaries": [42]}},
    {"leak_detection": {"min_unique_leaf_values": 0}}, {"leak_detection": {"min_unique_leaf_values": True}},
    {"leak_detection": {"ignore_fields": [""]}}, {"leak_detection": {"ignore_fields": ["a", "a"]}},
    {"acceptable_status": [200]}, {"acceptable_status": [429]}, {"acceptable_status": [500]},
    {"acceptable_status": [403, 403]}, {"acceptable_status": [True]},
    {"controls": {"nonexistent": True}}, {"controls": {"unauthenticated": "yes"}},
    {"confirm": True}, {"confirm": -1}, {"confirm": 101},
    {"auth_contexts": {"primary": "owner"}}, {"auth_contexts": {"primary": "owner", "forbidden": "owner"}},
    {"assertions": [{"type": "status_code", "expected": 403}]},
])
def test_invalid_differential_rules_fail_before_http(changes):
    selected = rule(**changes)
    with pytest.raises(ValueError):
        scan(lambda r: pytest.fail("invalid rule reached transport"), selected)


def test_unresolved_canary_is_error_before_http():
    selected = rule(leak_detection={"canaries": ["{{missing}}"]})
    result, requests = scan(lambda r: pytest.fail("invalid canary reached transport"), selected)
    assert result["verdict"] == "ERROR"
    assert requests == []


def test_all_new_fields_require_explicit_opt_in():
    selected = rule()
    selected.pop("leak_detection")
    selected.update(confirm=2, assertions=[{"type": "status_code", "expected": 403}])
    with pytest.raises(ValueError):
        scan(lambda r: pytest.fail("invalid rule reached transport"), selected)


@pytest.mark.parametrize("schema,current", [
    ({"type": "string", "format": "uuid"}, "00000000-0000-4000-8000-000000000000"),
    ({"type": "integer", "minimum": 1, "maximum": 1000}, 1),
    ({"type": "string", "pattern": "^usr_[a-f0-9]{8}$"}, "usr_abcdef12"),
    ({"type": "string", "minLength": 6, "maxLength": 6}, "ABC123"),
])
def test_type_aware_nonexistent_candidates(schema, current):
    generated = _nonexistent_value(schema, current)
    assert generated is not _MISSING
    assert generated != current
    if schema.get("format") == "uuid":
        UUID(generated)
    if schema["type"] == "integer":
        assert 1 <= generated <= 1000 and type(generated) is int
    if "pattern" in schema:
        assert re.search(schema["pattern"], generated)
    if "maxLength" in schema:
        assert len(generated) == 6


def test_query_object_control_preserves_exact_target_input():
    inv = inventory()
    inv["endpoints"][0].update(path="/objects", parameters=[{"name": "id", "in": "query", "required": True, "schema": {"type": "integer"}}])
    selected = rule(target_endpoints=[{"path": "/objects", "method": "GET"}])
    def handler(request):
        if request.headers.get("X-Actor") == "owner":
            return httpx.Response(200, json=OWNER)
        if request.url.params.get("id") != "42":
            return httpx.Response(404, json={"error": "missing"})
        return httpx.Response(200 if request.headers.get("X-Actor") else 401, json=OWNER)
    result, requests = scan(handler, selected, inv, {"id": 42})
    assert result["verdict"] == "FAIL"
    assert sum(r.url.params["id"] != "42" for r in requests) == 1


def test_read_only_blocks_every_control_and_confirmation_path():
    selected = rule(target_endpoints=[{"path": "/objects/{id}", "method": "POST"}])
    result, requests = scan(scenario_handler("bola"), selected, inventory(method="POST"), read_only=True)
    assert (result["status"], result["reason"]) == ("skipped", "safety_blocked")
    assert not requests
    # Explicitly permitting the original path does not authorize a mutated control path.
    result, requests = scan(scenario_handler("bola"), selected, inventory(method="POST"), read_only=True,
                            allow_mutations=(("POST", "/objects/object-a"),))
    assert (result["status"], result["reason"]) == ("skipped", "safety_blocked")
    assert len(requests) == 2


def test_rate_limit_covers_controls_and_confirmations_and_429_cooldown():
    async def execute():
        timestamps = []
        def handler(request):
            timestamps.append(monotonic())
            return scenario_handler("bola")(request)
        async with GuardedClient(max_rps=100, read_only=True, transport=httpx.MockTransport(handler)) as client:
            result = (await run_rules(inventory(), [rule()], client, CONTEXTS, {"id": "object-a"}))[0]
        assert result["verdict"] == "FAIL"
        assert len(timestamps) == 6
        assert all(b - a >= 0.008 for a, b in zip(timestamps, timestamps[1:]))
        timestamps.clear()
        def limited(request):
            timestamps.append(monotonic())
            if request.url.path == "/after":
                return httpx.Response(200)
            response = scenario_handler("429")(request)
            if response.status_code == 429:
                response.headers["Retry-After"] = "0.03"
            return response
        async with GuardedClient(max_rps=10000, concurrency=4, transport=httpx.MockTransport(limited)) as client:
            result = (await run_rules(inventory(), [rule()], client, CONTEXTS, {"id": "object-a"}))[0]
            assert (result["verdict"], result["reason"]) == ("INCONCLUSIVE", "rate_limited")
            assert client.current_limit == 2
            await client.get("https://target.test/after")
        assert timestamps[-1] - timestamps[-2] >= 0.025
    asyncio.run(execute())


def test_bundled_policy_and_legacy_copy_load_without_mutation():
    differential, legacy = load_rules(["rulesets/abac_isolation.yaml"]), load_rules(["rulesets/legacy_status_only.yaml"])
    assert "leak_detection" in differential[0]
    assert "assertions" not in differential[0]
    assert legacy[0]["assertions"] == [{"type": "status_code", "expected": 403}]
