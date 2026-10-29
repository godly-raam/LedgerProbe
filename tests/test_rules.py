"""Run from the repository root: python -m unittest discover -s tests -p test_rules.py."""

import copy
import datetime
import io
import json
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import yaml

from pkg.guardrails import GuardedClient, UnsafeRequest
from pkg.parser import build_graph, parse_document
from pkg.rules import load_rules, run_rules


def rule(**changes):
    value = {
        "id": "ownership", "name": "Same-object authorization", "severity": "high",
        "owasp_category": "API1:2023", "cvss_score": 8.1,
        "target_endpoints": [{"path": "/items/{id}", "method": "GET"}],
        "auth_contexts": {"primary": "alice", "forbidden": "bob"},
        "assertions": [{"type": "status_code", "expected": 403}],
    }
    value.update(changes)
    return value


def endpoint(path="/items/{id}", method="GET", operation_id="getItem", parameters=None, **extra) -> dict[str, Any]:
    if parameters is None:
        parameters = [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}]
    return dict(path=path, method=method, operation_id=operation_id, parameters=parameters,
                request_body={}, security=[], response_fields=["id"], **extra)


def inventory(*endpoints, graph=None):
    return {"base_url": "https://bank.test/api", "endpoints": list(endpoints) or [endpoint()],
            "graph": graph or []}


def response(status=200, payload=None, headers=None):
    return httpx.Response(status, json={} if payload is None else payload, headers=headers)


CONTEXTS = {"alice": {"Authorization": "Bearer ALICE-SECRET"},
            "bob": {"authorization": "Bearer BOB-SECRET"}}


class LoadRulesTests(unittest.TestCase):
    def load(self, *documents):
        streams = [io.StringIO(doc) for doc in documents]
        with patch.object(Path, "open", side_effect=streams):
            return load_rules([f"rules-{index}.yaml" for index in range(len(documents))])

    def test_supported_document_shapes_and_order(self):
        a, b, c = rule(), rule(id="two"), rule(id="three")
        result = self.load(yaml.safe_dump(a), yaml.safe_dump([b]), yaml.safe_dump({"rules": [c]}))
        self.assertEqual(result, [a, b, c])
        self.assertEqual(load_rules(iter([])), [])

    def test_duplicate_ids_and_yaml_keys_rejected(self):
        for docs in [(yaml.safe_dump([rule(), rule()]),),
                     (yaml.safe_dump(rule()), yaml.safe_dump(rule())),
                     ("id: one\nid: two",)]:
            with self.subTest(docs=docs), self.assertRaises(ValueError):
                self.load(*docs)

    def test_unsafe_malformed_and_non_json_yaml_rejected(self):
        for text in ["!!python/object/apply:os.system ['echo unsafe']", "rules: [",
                     "rules: null", "null", "1: invalid", "rules: []\nextra: true"]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.load(text)
        with self.assertRaises(ValueError):
            self.load(yaml.safe_dump(rule(body={"when": datetime.date(2026, 1, 1)})))
        with self.assertRaises(ValueError):
            load_rules("one.yaml")

    def test_strict_rule_validation(self):
        invalid = [
            {"severity": "urgent"}, {"severity": ["high"]}, {"id": 4}, {"name": " "},
            {"cvss_score": True}, {"cvss_score": "8.1"}, {"cvss_score": -1},
            {"cvss_score": 11}, {"cvss_score": float("nan")}, {"cvss_score": float("inf")},
                        {"cvss_score": 10 ** 1000},
            {"extra": "unknown"}, {"target_endpoints": []},
            {"target_endpoints": [{"path": "/items", "method": "get"}]},
            {"target_endpoints": [{"path": "https://evil.test", "method": "GET"}]},
            {"target_endpoints": [{"path": "/../items", "method": "GET"}]},
            {"auth_contexts": {"primary": 2}}, {"auth_contexts": {"other": "bob"}},
            {"parameters": {"cookie": {"id": 1}}}, {"parameters": {"path": []}},
            {"parameters": {"header": {"X-Mode": "a", "x-mode": "b"}}},
            {"assertions": []}, {"assertions": [{"type": "unknown"}]},
            {"assertions": [{"type": "status_code", "expected": True}]},
            {"assertions": [{"type": "status_code", "expected": "403"}]},
            {"assertions": [{"type": "status_code", "expected": 600}]},
            {"assertions": [{"type": "status_code", "expected": 403, "extra": 1}]},
            {"assertions": [{"type": "header", "name": "X", "expected": 1}]},
            {"assertions": [{"type": "body", "path": "x"}]},
            {"assertions": [{"type": "body", "path": "x", "exists": "false"}]},
            {"assertions": [{"type": "body", "path": "x", "value_type": "uuid"}]},
            {"assertions": [{"type": "body", "path": "x", "exists": False, "expected": 1}]},
        ]
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.load(yaml.safe_dump(rule(**changes)))

    def test_recursive_yaml_is_rejected(self):
        text = yaml.safe_dump(rule()) + "body: &loop\n  child: *loop\n"
        with self.assertRaises(ValueError):
            self.load(text)


class RunRulesTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.client = AsyncMock()
        self.client.request.side_effect = [response(200), response(403)]

    async def run_rule(self, selected=None, inv=None, variables=None, contexts=None):
        return (await run_rules(inv or inventory(), [selected or rule()], self.client,
                                CONTEXTS if contexts is None else contexts,
                                {"id": "owned"} if variables is None else variables))[0]

    async def test_primary_then_forbidden_same_inputs_and_redacted_result(self):
        selected = rule(parameters={"path": {"id": "{{account.id}}"},
                                    "query": {"limit": "{{limit}}"},
                                    "header": {"X-Mode": "check"}},
                        body={"owner": "{{account.id}}", "amount": "{{amount}}"})
        original = copy.deepcopy(selected)
        result = await self.run_rule(selected, variables={"account": {"id": "OWNED-SECRET"},
                                                          "limit": 2, "amount": 100})
        self.assertEqual(result["status"], "passed")
        first, second = self.client.request.call_args_list
        self.assertEqual(first.args, ("GET", "https://bank.test/api/items/OWNED-SECRET"))
        self.assertEqual(first.args, second.args)
        self.assertEqual(first.kwargs["params"], {"limit": 2})
        self.assertEqual(first.kwargs["json"], {"owner": "OWNED-SECRET", "amount": 100})
        self.assertEqual(first.kwargs["json"], second.kwargs["json"])
        self.assertFalse(first.kwargs["follow_redirects"])
        self.assertEqual(first.kwargs["headers"]["authorization"], "Bearer ALICE-SECRET")
        self.assertEqual(second.kwargs["headers"]["authorization"], "Bearer BOB-SECRET")
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertEqual(selected, original)
        self.assertEqual(set(result), {"rule_id", "name", "severity", "owasp_category", "cvss_score",
                                       "path", "method", "status", "message", "assertions"})

    async def test_failed_baseline_never_sends_forbidden(self):
        for status in (301, 401, 403, 404, 500):
            with self.subTest(status=status):
                self.client.request.reset_mock()
                self.client.request.side_effect = [response(status)]
                result = await self.run_rule()
                self.assertEqual(result["status"], "error")
                self.assertEqual(self.client.request.await_count, 1)
                self.assertNotIn("assertions", result)

    async def test_optional_baseline_and_anonymous_forbidden(self):
        for auth in ({"forbidden": "bob"}, {}):
            with self.subTest(auth=auth):
                self.client.request.reset_mock()
                self.client.request.side_effect = [response(403)]
                result = await self.run_rule(rule(auth_contexts=auth))
                self.assertEqual(result["status"], "passed")
                self.assertEqual(self.client.request.await_count, 1)
        self.client.request.side_effect = [response(200), response(403)]
        await self.run_rule(rule(auth_contexts={"primary": "alice"}))
        self.assertEqual(self.client.request.call_args.kwargs["headers"], {"cookie": ""})

    async def test_status_header_and_body_assertions(self):
        selected = rule(assertions=[
            {"type": "status_code", "expected": 403},
            {"type": "header", "name": "X-RESULT", "expected": "denied"},
            {"type": "body", "path": "data.0.id", "expected": "{{expected.id}}", "value_type": "integer"},
            {"type": "body", "path": "data.0.null", "exists": True, "value_type": "null"},
            {"type": "body", "path": "data.0.missing", "exists": False},
            {"type": "body", "path": "", "value_type": "object"},
        ])
        self.client.request.side_effect = [response(), response(403, {"data": [{"id": 42, "null": None}]},
                                                               {"x-result": "denied"})]
        result = await self.run_rule(selected, variables={"id": "owned", "expected": {"id": 42}})
        self.assertEqual(result["status"], "passed")
        self.assertTrue(all(item["passed"] for item in result["assertions"]))

    async def test_failed_assertions_and_non_json_do_not_expose_values(self):
        selected = rule(assertions=[{"type": "body", "path": "secret", "expected": "EXPECTED-SECRET"}])
        self.client.request.side_effect = [response(), response(200, {"secret": "ACTUAL-SECRET"})]
        result = await self.run_rule(selected)
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("SECRET", json.dumps(result))
        self.client.request.side_effect = [response(), httpx.Response(403, text="NOT-JSON-SECRET")]
        result = await self.run_rule(rule(assertions=[{"type": "body", "path": "x", "exists": False}]))
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("SECRET", json.dumps(result))

    async def test_boolean_is_not_a_json_number(self):
        self.client.request.side_effect = [response(), response(403, {"x": True})]
        result = await self.run_rule(rule(assertions=[{"type": "body", "path": "x", "expected": 1}]))
        self.assertEqual(result["status"], "failed")

    async def test_missing_inputs_fail_closed_without_http(self):
        for location in ("path", "query", "header", "cookie"):
            with self.subTest(location=location):
                self.client.request.reset_mock()
                ep = endpoint(parameters=[{"name": "needed", "in": location, "required": True,
                                           "schema": {"type": "string", "default": "FAKE"},
                                           "example": "FAKE"}])
                result = await self.run_rule(inv=inventory(ep), variables={})
                self.assertEqual(result["status"], "error")
                self.client.request.assert_not_awaited()
        self.client.request.reset_mock()
        result = await self.run_rule(rule(parameters={"path": {"id": "{{missing.id}}"}}))
        self.assertEqual(result["status"], "error")
        self.client.request.assert_not_awaited()

    async def test_endpoint_base_mismatch_fails_before_dependencies_or_http(self):
        source = endpoint("/source", "GET", "source", [])
        for base in ("https://other.test/api", "https://bank.test/other", "", None):
            with self.subTest(base=base):
                target = endpoint(base_url=base)
                inv = inventory(source, target, graph=[
                    {"source": "source", "target": "getItem", "field": "id", "parameter": "id"}])
                result = await self.run_rule(inv=inv, variables={})
                self.assertEqual(result["status"], "error")
                self.assertIn("base_url", result["message"])
                self.client.request.assert_not_awaited()

    async def test_parsed_server_and_postman_origin_overrides_fail_closed(self):
        for level in ("path", "operation", "postman"):
            with self.subTest(level=level):
                if level == "postman":
                    document = {"info": {"name": "Test", "schema":
                        "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"}, "item": [
                        {"request": {"method": "GET", "url": "https://bank.test/source"}},
                        {"request": {"method": "GET", "url": "https://other.test/use"}}]}
                else:
                    operation: dict[str, Any] = {"responses": {"200": {"description": "OK"}}}
                    path_item: dict[str, Any] = {"get": operation}
                    if level == "operation":
                        path_item["servers"] = [{"url": "https://bank.test/api"}]
                        operation["servers"] = [{"url": "https://other.test/api"}]
                    else:
                        path_item["servers"] = [{"url": "https://other.test/api"}]
                    document = {"openapi": "3.0.3", "info": {"title": "Test", "version": "1"},
                        "servers": [{"url": "https://bank.test/api"}], "paths": {"/use": path_item}}
                inv = parse_document(document)
                target = inv["endpoints"][-1]
                self.assertNotEqual(target["base_url"], inv["base_url"])
                result = await self.run_rule(rule(target_endpoints=[{"path": "/use", "method": "GET"}]),
                                             inv, variables={})
                self.assertEqual(result["status"], "error")
                self.assertIn("base_url", result["message"])
                self.client.request.assert_not_awaited()

    async def test_dependency_base_mismatch_fails_closed(self):
        source = endpoint("/source", "GET", "source", [], base_url="https://other.test/api")
        inv = inventory(source, endpoint(), graph=[
            {"source": "source", "target": "getItem", "field": "id", "parameter": "id"}])
        result = await self.run_rule(inv=inv, variables={})
        self.assertEqual(result["status"], "error")
        self.assertIn("base_url", result["message"])
        self.client.request.assert_not_awaited()

    async def test_equal_base_and_deliberate_all_endpoint_override(self):
        inv = inventory(endpoint(base_url="https://bank.test/api"))
        result = await self.run_rule(inv=inv)
        self.assertEqual(result["status"], "passed")
        inv["base_url"] = "https://override.test/v2"
        for ep in inv["endpoints"]:
            ep.pop("base_url", None)
        self.client.request.side_effect = [response(), response(403)]
        result = await self.run_rule(inv=inv)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(self.client.request.call_args.args[1], "https://override.test/v2/items/owned")

    async def test_required_query_header_and_context_headers(self):
        ep = endpoint(parameters=[{"name": "id", "in": "path", "required": True},
                                  {"name": "page", "in": "query", "required": True},
                                  {"name": "X-Mode", "in": "header", "required": True},
                                  {"name": "Authorization", "in": "header", "required": True}])
        result = await self.run_rule(inv=inventory(ep), variables={"id": "owned", "query.page": 0,
                                                                  "header.X-Mode": "read"})
        self.assertEqual(result["status"], "passed")
        self.assertEqual(self.client.request.call_args.kwargs["params"], {"page": 0})
        self.assertEqual(self.client.request.call_args.kwargs["headers"]["x-mode"], "read")
        self.client.request.reset_mock()
        result = await self.run_rule(rule(auth_contexts={"primary": "alice"}), inv=inventory(ep),
                                     variables={"id": "owned", "page": 1, "X-Mode": "read"})
        self.assertEqual(result["status"], "error")
        self.client.request.assert_not_awaited()

    async def test_parameter_headers_are_case_insensitive(self):
        ep = endpoint(parameters=[{"name": "X-Mode", "in": "header", "required": True}])
        result = await self.run_rule(rule(parameters={"header": {"x-mode": "read"}}), inventory(ep))
        self.assertEqual(result["status"], "passed")
        self.assertEqual(self.client.request.call_args.kwargs["headers"]["x-mode"], "read")

    async def test_custom_context_headers_cannot_leak_through_shared_parameters(self):
        contexts = {"alice": {"X-Api-Key": "ALICE-SECRET"}, "bob": {}}
        result = await self.run_rule(rule(parameters={"header": {"X-Api-Key": "ALICE-SECRET"}}),
                                     contexts=contexts)
        self.assertEqual(result["status"], "error")
        self.client.request.assert_not_awaited()
        self.assertNotIn("SECRET", json.dumps(result))

    async def test_path_values_cannot_change_host_or_path_structure(self):
        for value in ("//evil.test/a?token=x#y", "../admin", "a/b", "a%2Fb", "x\\y"):
            with self.subTest(value=value):
                self.client.request.side_effect = [response(), response(403)]
                result = await self.run_rule(variables={"id": value})
                self.assertEqual(result["status"], "passed")
                url = self.client.request.call_args.args[1]
                self.assertTrue(url.startswith("https://bank.test/api/items/"))
                segment = url.removeprefix("https://bank.test/api/items/")
                self.assertNotIn("/", segment)
                self.assertNotIn("?", segment)
                self.assertNotIn("#", segment)
        for value in (".", "..", "", None, {}):
            with self.subTest(value=value):
                self.client.request.reset_mock()
                result = await self.run_rule(variables={"id": value})
                self.assertEqual(result["status"], "error")
                self.client.request.assert_not_awaited()

    async def test_required_body_properties_and_explicit_json_types(self):
        ep = endpoint(path="/payments", method="POST", parameters=[])
        ep["request_body"] = {"required": True, "content": {"application/json": {"schema": {
            "type": "object", "required": ["account", "amount"], "properties": {
                "account": {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}},
                "amount": {"type": "integer"}}}}}}
        selected = rule(target_endpoints=[{"path": "/payments", "method": "POST"}])
        result = await self.run_rule(selected, inventory(ep), variables={"body.account.id": "owned", "amount": 0})
        self.assertEqual(result["status"], "passed")
        self.assertEqual(self.client.request.call_args.kwargs["json"], {"account": {"id": "owned"}, "amount": 0})
        for variables, body in [({}, {}), ({}, {"account": {"id": "owned"}, "amount": True}),
                                ({}, "not-an-object")]:
            with self.subTest(body=body):
                self.client.request.reset_mock()
                result = await self.run_rule(dict(selected, body=body), inventory(ep), variables=variables)
                self.assertEqual(result["status"], "error")
                self.client.request.assert_not_awaited()

    async def test_unsupported_body_schemas_and_optional_body(self):
        for request_body in [
            {"required": True, "content": {"multipart/form-data": {"schema": {"type": "object"}}}},
            {"$ref": "#/requestBodies/Missing", "required": True},
            {"$ref": "#/requestBodies/Missing"},
            {"required": True, "content": {"application/json": {"schema": {"$ref": "#/missing"}}}},
            {"required": True, "content": {"application/json": {"schema": {"$dynamicRef": "#node"}}}},
            {"required": True, "content": {"application/json": {"schema": {"$recursiveRef": "#"}}}},
            {"required": True, "content": {"application/json": {"schema": {"allOf": []}}}},
        ]:
            with self.subTest(request_body=request_body):
                self.client.request.reset_mock()
                ep = endpoint()
                ep["request_body"] = request_body
                result = await self.run_rule(inv=inventory(ep))
                self.assertEqual(result["status"], "error")
                self.client.request.assert_not_awaited()
        ep = endpoint()
        ep["request_body"] = {"content": {"application/json": {"schema": {"type": "object", "required": ["x"]}}}}
        result = await self.run_rule(inv=inventory(ep))
        self.assertEqual(result["status"], "passed")
        self.assertNotIn("json", self.client.request.call_args.kwargs)

    async def test_parsed_recursive_body_cannot_bypass_validation(self):
        ref = "#/components/schemas/Node"
        document = {"openapi": "3.0.3", "info": {"title": "Test", "version": "1"},
            "servers": [{"url": "https://bank.test/api"}],
            "components": {"schemas": {"Node": {"type": "object", "required": ["next"],
                "properties": {"next": {"$ref": ref}}}}},
            "paths": {"/nodes": {"post": {"requestBody": {"required": True, "content": {
                "application/json": {"schema": {"$ref": ref}}}},
                "responses": {"200": {"description": "OK"}}}}}}
        inv = parse_document(document)
        result = await self.run_rule(rule(target_endpoints=[{"path": "/nodes", "method": "POST"}],
                                          body={"next": {}}), inv, variables={})
        self.assertEqual(result["status"], "error")
        self.assertIn("schema is unresolved", result["message"])
        self.client.request.assert_not_awaited()

    async def test_inferred_nested_response_to_required_body_executes(self):
        source = endpoint("/source", "GET", "source", [])
        source["response_fields"] = ["data", "data.account_id"]
        target = endpoint("/use", "POST", "use", [])
        target["request_body"] = {"required": True, "content": {"application/json": {"schema": {
            "type": "object", "required": ["account_id"], "properties": {"account_id": {"type": "string"}}}}}}
        inv = inventory(source, target, graph=build_graph([source, target]))
        self.client.request.side_effect = [response(200, {"data": {"account_id": "owned"}}),
                                           response(), response(403)]
        result = await self.run_rule(rule(target_endpoints=[{"path": "/use", "method": "POST"}]),
                                     inv, variables={})
        self.assertEqual(result["status"], "passed")
        calls = self.client.request.call_args_list
        self.assertEqual([call.args[0] for call in calls], ["GET", "POST", "POST"])
        self.assertEqual(calls[1].kwargs["json"], {"account_id": "owned"})
        self.assertEqual(calls[2].kwargs["json"], calls[1].kwargs["json"])

    async def test_only_selected_targets_and_required_dependencies_execute(self):
        create = endpoint("/items", "POST", "createItem", [])
        graph = [{"source": "createItem", "target": "getItem", "field": "id", "parameter": "id"}]
        inv = inventory(create, endpoint(), endpoint("/unselected", "DELETE", "unselected", []), graph=graph)
        self.client.request.side_effect = [response(201, {"data": {"id": "created"}}), response(), response(403)]
        result = await self.run_rule(inv=inv, variables={})
        self.assertEqual(result["status"], "passed")
        calls = self.client.request.call_args_list
        self.assertEqual([call.args[0] for call in calls], ["POST", "GET", "GET"])
        self.assertEqual(calls[1].args[1], "https://bank.test/api/items/created")
        self.assertEqual(calls[0].kwargs["headers"]["authorization"], "Bearer ALICE-SECRET")
        self.assertEqual(calls[1].kwargs["headers"]["authorization"], "Bearer ALICE-SECRET")
        self.assertEqual(calls[2].kwargs["headers"]["authorization"], "Bearer BOB-SECRET")
        self.client.request.reset_mock()
        self.client.request.side_effect = [response(), response(403)]
        await self.run_rule(inv=inv, variables={"id": "explicit"})
        self.assertEqual(self.client.request.await_count, 2)

    async def test_optional_graph_parameters_do_not_run_dependencies(self):
        ep = endpoint(parameters=[{"name": "page", "in": "query", "required": False}])
        inv = inventory(ep, endpoint("/create", "POST", "create", []), graph=[
            {"source": "create", "target": "getItem", "field": "page", "parameter": "page"}])
        result = await self.run_rule(inv=inv)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(self.client.request.await_count, 2)
        self.assertEqual(self.client.request.call_args.kwargs["params"], {})

    async def test_response_ids_from_primary_only_and_context_scoped(self):
        source = endpoint("/create", "POST", "createItem", [])
        inv = inventory(source, endpoint(), graph=[
            {"source": "createItem", "target": "getItem", "field": "id", "parameter": "id"}])
        create_rule = rule(id="create", target_endpoints=[{"path": "/create", "method": "POST"}],
                           assertions=[{"type": "status_code", "expected": 200}])
        another = rule(id="another", auth_contexts={"primary": "charlie", "forbidden": "bob"})
        contexts = dict(CONTEXTS, charlie={"Authorization": "Bearer CHARLIE-SECRET"})
        self.client.request.side_effect = [response(201, {"id": "alice-id"}), response(200, {"id": "POISON"}),
                                           response(), response(403), response(201, {"id": "charlie-id"}),
                                           response(), response(403)]
        results = await run_rules(inv, [create_rule, rule(), another], self.client, contexts)
        self.assertEqual([r["status"] for r in results], ["passed", "passed", "passed"])
        calls = self.client.request.call_args_list
        self.assertTrue(calls[2].args[1].endswith("/items/alice-id"))
        self.assertTrue(calls[3].args[1].endswith("/items/alice-id"))
        self.assertEqual(calls[4].args[0], "POST")
        self.assertEqual(calls[4].kwargs["headers"]["authorization"], "Bearer CHARLIE-SECRET")
        self.assertTrue(calls[5].args[1].endswith("/items/charlie-id"))
        self.assertNotIn("POISON", json.dumps(results))

    async def test_dependency_state_does_not_cross_contexts_or_runs(self):
        source = endpoint("/source", "GET", "source", [])
        inv = inventory(source, endpoint(), graph=[
            {"source": "source", "target": "getItem", "field": "id", "parameter": "id"}])
        contexts = copy.deepcopy(CONTEXTS)
        variables = {}
        original = copy.deepcopy((inv, contexts, variables))
        bob_rule = rule(id="bob-primary", auth_contexts={"primary": "bob", "forbidden": "alice"})
        self.client.request.side_effect = [response(200, {"id": "alice-id"}), response(), response(403),
                                           response(200, {}), response(200, {})]
        results = await run_rules(inv, [rule(), bob_rule], self.client, contexts, variables)
        self.assertEqual([r["status"] for r in results], ["passed", "error"])
        self.assertEqual(self.client.request.call_args_list[3].kwargs["headers"]["authorization"],
                         "Bearer BOB-SECRET")
        # A new run with the same context cannot reuse the previous run's response.
        results = await run_rules(inv, [rule()], self.client, contexts, variables)
        self.assertEqual(results[0]["status"], "error")
        self.assertEqual(self.client.request.await_count, 5)
        self.assertEqual((inv, contexts, variables), original)

    async def test_inferred_ambiguous_leaf_edges_fail_before_http(self):
        source = endpoint("/source", "GET", "source", [])
        source["response_fields"] = ["id", "data.id"]
        inv = inventory(source, endpoint(), graph=build_graph([source, endpoint()]))
        result = await self.run_rule(inv=inv, variables={})
        self.assertEqual(result["status"], "error")
        self.assertIn("Ambiguous", result["message"])
        self.client.request.assert_not_awaited()

    async def test_dependency_chain_and_body_graph_input(self):
        create = endpoint("/create", "POST", "create", [])
        child = endpoint("/child/{parent_id}", "POST", "child", [
            {"name": "parent_id", "in": "path", "required": True}])
        target = endpoint("/use", "POST", "use", [])
        target["request_body"] = {"required": True, "content": {"application/json": {"schema": {
            "type": "object", "required": ["child_id"], "properties": {"child_id": {"type": "string"}}}}}}
        graph = [{"source": "create", "target": "child", "field": "data.id", "parameter": "parent_id"},
                 {"source": "child", "target": "use", "field": "id", "parameter": "child_id"}]
        self.client.request.side_effect = [response(201, {"data": {"id": "parent"}}),
                                           response(201, {"id": "child"}), response(), response(403)]
        result = await self.run_rule(rule(target_endpoints=[{"path": "/use", "method": "POST"}]),
                                     inventory(create, child, target, graph=graph), variables={})
        self.assertEqual(result["status"], "passed")
        self.assertTrue(self.client.request.call_args_list[1].args[1].endswith("/child/parent"))
        self.assertEqual(self.client.request.call_args.kwargs["json"], {"child_id": "child"})

    async def test_dependencies_fail_closed(self):
        create = endpoint("/create", "POST", "create", [])
        graph = [{"source": "create", "target": "getItem", "field": "id", "parameter": "id"}]
        for dependency_response in (response(401), response(200, {}),
                                    response(200, {"a": {"id": "one"}, "b": {"id": "two"}}),
                                    response(200, {"id": "one", "data": {"id": "two"}}),
                                    response(200, [{"id": "only-item"}]),
                                    response(200, {"data": [{"id": "only-item"}]})):
            with self.subTest(response=dependency_response):
                self.client.request.reset_mock()
                self.client.request.side_effect = [dependency_response]
                result = await self.run_rule(inv=inventory(create, endpoint(), graph=graph), variables={})
                self.assertEqual(result["status"], "error")
                self.assertEqual(self.client.request.await_count, 1)
        self.client.request.reset_mock()
        result = await self.run_rule(rule(auth_contexts={"forbidden": "bob"}),
                                     inventory(create, endpoint(), graph=graph), variables={})
        self.assertEqual(result["status"], "error")
        self.client.request.assert_not_awaited()

    async def test_cycles_depth_and_ambiguous_edges_are_bounded(self):
        cyclic = [{"source": "getItem", "target": "getItem", "field": "id", "parameter": "id"}]
        result = await self.run_rule(inv=inventory(graph=cyclic), variables={})
        self.assertEqual(result["status"], "error")
        self.client.request.assert_not_awaited()
        nodes = [endpoint(f"/node{i}/{{id}}", "GET", f"op{i}") for i in range(20)]
        graph = [{"source": f"op{i+1}", "target": f"op{i}", "field": "id", "parameter": "id"}
                 for i in range(19)]
        selected = rule(target_endpoints=[{"path": "/node0/{id}", "method": "GET"}])
        result = await self.run_rule(selected, inventory(*nodes, graph=graph), variables={})
        self.assertEqual(result["status"], "error")
        self.client.request.assert_not_awaited()
        result = await self.run_rule(inv=inventory(graph=cyclic + cyclic), variables={})
        self.assertEqual(result["status"], "error")
        self.client.request.assert_not_awaited()

    async def test_guard_blocks_and_transport_errors_are_not_findings(self):
        for exc, expected in [(UnsafeRequest("SECRET"), "skipped"),
                              (RuntimeError("SECRET"), "error")]:
            for stage in ("primary", "forbidden", "dependency"):
                with self.subTest(exc=type(exc), stage=stage):
                    self.client.request.reset_mock()
                    self.client.request.side_effect = [response(), exc] if stage == "forbidden" else [exc]
                    inv = inventory()
                    variables = {"id": "owned"}
                    if stage == "dependency":
                        inv = inventory(endpoint("/create", "POST", "create", []), endpoint(), graph=[
                            {"source": "create", "target": "getItem", "field": "id", "parameter": "id"}])
                        variables = {}
                    result = await self.run_rule(inv=inv, variables=variables)
                    self.assertEqual(result["status"], expected)
                    self.assertNotIn("SECRET", json.dumps(result))

    async def test_real_guarded_client_does_not_forward_baseline_cookies(self):
        requests = []

        def handler(request):
            requests.append(request)
            if len(requests) == 1:
                return response(200, headers={"Set-Cookie": "session=ALICE-SECRET; Path=/"})
            return response(403)

        async with GuardedClient(max_rps=100000, transport=httpx.MockTransport(handler)) as client:
            results = await run_rules(inventory(), [rule()], client, CONTEXTS, {"id": "a/b"})
        self.assertEqual(results[0]["status"], "passed")
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0].url.raw_path, b"/api/items/a%2Fb")
        self.assertEqual(requests[1].headers["authorization"], "Bearer BOB-SECRET")
        self.assertEqual(requests[1].headers.get("cookie"), "")

    async def test_real_guarded_client_blocks_dependency_mutation(self):
        transport = httpx.MockTransport(lambda request: self.fail("Blocked dependency reached transport"))
        inv = inventory(endpoint("/create", "POST", "create", []), endpoint(), graph=[
            {"source": "create", "target": "getItem", "field": "id", "parameter": "id"}])
        async with GuardedClient(read_only=True, transport=transport) as client:
            results = await run_rules(inv, [rule()], client, CONTEXTS)
        self.assertEqual(results[0]["status"], "skipped")

    async def test_unknown_endpoint_missing_context_and_per_endpoint_results(self):
        selected = rule(target_endpoints=[{"path": "/unknown", "method": "GET"},
                                           {"path": "/items/{id}", "method": "GET"}])
        results = await run_rules(inventory(), [selected], self.client, CONTEXTS, {"id": "owned"})
        self.assertEqual([r["status"] for r in results], ["skipped", "passed"])
        self.client.request.reset_mock()
        result = await self.run_rule(contexts={})
        self.assertEqual(result["status"], "error")
        self.client.request.assert_not_awaited()

    async def test_validation_precedes_all_http(self):
        invalid_configs = [([rule(), rule(id="bad", cvss_score=True)], CONTEXTS, {}),
                           ([rule()], {"alice": {"Authorization": "bad\r\nInjected: yes"}}, {}),
                           ([rule()], {"alice": {"Host": "evil.test"}}, {}),
                           ([rule()], {"alice": {"authorization": "a", "Authorization": "b"}}, {}),
                           ([rule()], CONTEXTS, {"value": object()})]
        for rules, contexts, variables in invalid_configs:
            with self.subTest(contexts=contexts), self.assertRaises(ValueError):
                await run_rules(inventory(), rules, self.client, contexts, variables)
            self.client.request.assert_not_awaited()
        for base in ("file:///etc/passwd", "//evil.test", "https://user:secret@bank.test", "https://bank.test/?x=1"):
            with self.subTest(base=base), self.assertRaises(ValueError):
                await run_rules(dict(inventory(), base_url=base), [rule()], self.client)
            self.client.request.assert_not_awaited()

    async def test_no_shared_auth_header_or_invalid_header_values(self):
        for headers in ({"Authorization": "secret"}, {"Host": "evil.test"},
                        {"X-Mode": "value\r\nInjected: yes"}):
            with self.subTest(headers=headers):
                result = await self.run_rule(rule(parameters={"header": headers}))
                self.assertEqual(result["status"], "error")
                self.client.request.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
