"""Run with: python -m unittest discover -s tests -p test_parser.py -v."""

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock, Mock, patch

import yaml

from pkg.parser import build_graph, load_inventory, parse_document

HAS_VALIDATOR = importlib.util.find_spec("openapi_spec_validator") is not None
POSTMAN_SCHEMA = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"


def collection(items=None, **extra):
    return {"info": {"name": "Example", "schema": POSTMAN_SCHEMA},
            "item": [] if items is None else items, **extra}


def request(url: Any = "https://bank.example/accounts", **extra):
    return {"name": "request", "request": {"method": "GET", "url": url, **extra}}


def openapi(version="3.0.3"):
    return {"openapi": version, "info": {"title": "Example", "version": "1"},
            "servers": [{"url": "https://bank.example/v1"}], "paths": {}}


class LoadingTests(unittest.IsolatedAsyncioTestCase):
    async def test_local_json_and_yaml(self):
        document = collection([request()])
        with tempfile.TemporaryDirectory() as directory:
            for suffix, text in (("json", json.dumps(document)), ("yaml", yaml.safe_dump(document))):
                with self.subTest(suffix=suffix):
                    path = Path(directory) / ("api." + suffix)
                    path.write_text(text, encoding="utf-8")
                    inventory = await load_inventory(str(path), None)
                    self.assertEqual(inventory["base_url"], "https://bank.example")
                    self.assertEqual(inventory["endpoints"][0]["method"], "GET")

    async def test_only_supplied_client_fetches(self):
        response = Mock(text=yaml.safe_dump(collection([request()])))
        client = Mock(get=AsyncMock(return_value=response))
        result = await load_inventory("https://spec.example/api.yaml", client)
        client.get.assert_awaited_once_with("https://spec.example/api.yaml")
        response.raise_for_status.assert_called_once_with()
        self.assertEqual(len(result["endpoints"]), 1)

    async def test_transport_error_propagates(self):
        client = Mock(get=AsyncMock(side_effect=RuntimeError("blocked")))
        with self.assertRaisesRegex(RuntimeError, "blocked"):
            await load_inventory("https://spec.example/api", client)

    async def test_http_error_propagates(self):
        response = Mock(text="{}")
        response.raise_for_status.side_effect = RuntimeError("HTTP 403")
        with self.assertRaisesRegex(RuntimeError, "HTTP 403"):
            await load_inventory("https://spec.example/api", Mock(get=AsyncMock(return_value=response)))

    async def test_bad_sources(self):
        for source in ("", "ftp://spec.example/api", "file:///tmp/api"):
            with self.subTest(source=source), self.assertRaises(ValueError):
                await load_inventory(source, None)
        with self.assertRaisesRegex(ValueError, "guarded client"):
            await load_inventory("https://spec.example/api", None)

    async def test_malformed_yaml_and_nonobject(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "api.yaml"
            for text in ("[invalid", "- not-an-object", "!!python/object:unsafe {}"):
                path.write_text(text, encoding="utf-8")
                with self.subTest(text=text), self.assertRaises(ValueError):
                    await load_inventory(str(path), None)


class RejectionTests(unittest.TestCase):
    def test_unsupported_documents(self):
        for document in (None, [], {}, {"openapi": "4.0.0"}, {"swagger": "1.2"},
                         collection(info={"name": "Old", "schema": POSTMAN_SCHEMA.replace("2.1.0", "2.0.0")})):
            with self.subTest(document=document), self.assertRaises(ValueError):
                parse_document(cast(Any, document))

    def test_external_refs_rejected_before_validation(self):
        for ref in ("https://evil.example/schema", "other.yaml#/Thing", "//evil/schema"):
            document = openapi()
            document["components"] = {"schemas": {"Unused": {"$ref": ref}}}
            with self.subTest(ref=ref), self.assertRaisesRegex(ValueError, "bundle references"):
                parse_document(document)

    def test_external_dynamic_refs_rejected(self):
        document = openapi("3.1.0")
        document["components"] = {"schemas": {"Unused": {"$dynamicRef": "https://evil.example/schema"}}}
        with self.assertRaisesRegex(ValueError, "bundle references"):
            parse_document(document)

    def test_missing_local_ref(self):
        document = openapi()
        document["components"] = {"schemas": {"Unused": {"$ref": "#/missing"}}}
        with self.assertRaisesRegex(ValueError, "Unresolved local"):
            parse_document(document)

    def test_missing_anchor(self):
        document = openapi("3.1.0")
        document["components"] = {"schemas": {"Unused": {"$ref": "#missing"}}}
        with self.assertRaisesRegex(ValueError, "Unresolved or ambiguous local"):
            parse_document(document)

    def test_yaml_alias_cycle_and_depth_limit(self):
        document = openapi()
        document["cycle"] = document
        with self.assertRaisesRegex(ValueError, "cycle"):
            parse_document(document)
        document = openapi()
        node = document
        for _ in range(110):
            node["nested"] = {}
            node = node["nested"]
        with self.assertRaisesRegex(ValueError, "nesting"):
            parse_document(document)


@unittest.skipUnless(HAS_VALIDATOR, "parent must provide openapi-spec-validator")
class OpenAPITests(unittest.TestCase):
    def test_openapi_30_refs_overrides_examples_security_and_graph(self):
        document = openapi()
        document["components"] = {
            "schemas": {"Account": {"type": "object", "properties": {
                "account_id": {"type": "string", "example": "acct-1"},
                "owner": {"type": "object", "properties": {"name": {"type": "string"}}}}}},
            "parameters": {"AccountID": {"name": "account_id", "in": "path", "required": True,
                                         "schema": {"type": "string"}, "example": "acct-1"}},
            "securitySchemes": {"Bearer": {"type": "http", "scheme": "bearer"}}}
        document["security"] = [{"Bearer": []}]
        document["paths"] = {
            "/accounts": {"post": {"operationId": "createAccount", "requestBody": {
                "required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Account"},
                "example": {"account_id": "acct-1"}}}}, "responses": {"201": {
                "description": "Created", "content": {"application/json": {
                    "schema": {"$ref": "#/components/schemas/Account"}}}}}}},
            "/accounts/{account_id}": {"parameters": [{"$ref": "#/components/parameters/AccountID"},
                {"name": "filter", "in": "query", "schema": {"type": "string"}, "example": "old"}],
                "get": {"operationId": "getAccount", "parameters": [
                    {"name": "filter", "in": "query", "schema": {"type": "string"}, "example": "new"}],
                    "security": [], "responses": {"200": {"description": "OK"}}}}}
        before = copy.deepcopy(document)
        result = parse_document(document)
        self.assertEqual(document, before)
        create, get = result["endpoints"]
        self.assertEqual(result["base_url"], "https://bank.example/v1")
        self.assertEqual(create["security"], [{"Bearer": []}])
        self.assertEqual(get["security"], [])
        self.assertEqual(create["request_body"]["content"]["application/json"]["example"], {"account_id": "acct-1"})
        self.assertEqual(create["response_fields"], ["account_id", "owner", "owner.name"])
        self.assertEqual(get["parameters"][0]["example"], "acct-1")
        self.assertEqual(get["parameters"][1]["example"], "new")
        self.assertEqual(result["graph"], [{"source": "createAccount", "target": "getAccount",
                                         "field": "account_id", "parameter": "account_id"}])

    def test_openapi_31_recursive_schema_and_server_variables(self):
        document = openapi("3.1.0")
        document["servers"] = [{"url": "https://{host}/v1", "variables": {"host": {"default": "bank.example"}}}]
        document["components"] = {"schemas": {"Node": {"type": "object", "properties": {
            "id": {"type": ["string", "null"]}, "next": {"$ref": "#/components/schemas/Node"}}}}}
        document["paths"] = {"/nodes": {"get": {"responses": {"200": {"description": "OK", "content": {
            "application/json": {"schema": {"$ref": "#/components/schemas/Node"}}}}}}}}
        result = parse_document(document)
        endpoint = result["endpoints"][0]
        self.assertEqual(result["base_url"], "https://bank.example/v1")
        self.assertEqual(endpoint["operation_id"], "GET /nodes")
        self.assertEqual(endpoint["response_fields"], ["id", "next"])
        self.assertIsNone(endpoint["request_body"])

    def test_recursive_body_keeps_unresolved_reference(self):
        document = openapi()
        ref = "#/components/schemas/Node"
        document["components"] = {"schemas": {"Node": {"type": "object", "required": ["next"],
            "properties": {"next": {"$ref": ref}}}}}
        document["paths"] = {"/nodes": {"post": {"requestBody": {"required": True,
            "content": {"application/json": {"schema": {"$ref": ref}}}},
            "responses": {"200": {"description": "OK"}}}}}
        schema = parse_document(document)["endpoints"][0]["request_body"]["content"]["application/json"]["schema"]
        self.assertEqual(schema["properties"]["next"], {"$ref": ref})

    def test_resolution_depth_does_not_erase_schema(self):
        document = openapi()
        schemas = {f"Node{i}": {"$ref": f"#/components/schemas/Node{i + 1}"} for i in range(45)}
        schemas["Node45"] = {"type": "string"}
        document["components"] = {"schemas": schemas}
        with self.assertRaisesRegex(ValueError, "resolution.*nesting limit"):
            parse_document(document)

    def test_nested_response_leaf_links_to_required_json_body(self):
        document = openapi()
        document["paths"] = {
            "/source": {"get": {"operationId": "source", "responses": {"200": {"description": "OK",
                "content": {"application/json": {"schema": {"type": "object", "properties": {
                    "data": {"type": "object", "properties": {"account_id": {"type": "string"}}}}}}}}}}},
            "/use": {"post": {"operationId": "use", "requestBody": {"required": True,
                "content": {"application/json": {"schema": {"type": "object", "required": ["account_id"],
                    "properties": {"account_id": {"type": "string"}}}}}},
                "responses": {"200": {"description": "OK"}}}}}
        self.assertEqual(parse_document(document)["graph"], [
            {"source": "source", "target": "use", "field": "data.account_id", "parameter": "account_id"}])

    def test_openapi2_body_forms_security_and_response(self):
        document = {"swagger": "2.0", "info": {"title": "Bank", "version": "1"},
            "host": "bank.example", "basePath": "/v2", "schemes": ["https"],
            "securityDefinitions": {"Key": {"type": "apiKey", "name": "X-Key", "in": "header"}},
            "security": [{"Key": []}], "definitions": {"Account": {"type": "object", "properties": {
                "account_id": {"type": "integer"}}}}, "paths": {
                "/accounts": {"post": {"consumes": ["application/json"], "parameters": [
                    {"name": "body", "in": "body", "required": True, "schema": {"$ref": "#/definitions/Account"}}],
                    "responses": {"200": {"description": "OK", "schema": {"$ref": "#/definitions/Account"}}}}},
                "/forms": {"post": {"consumes": ["multipart/form-data"], "parameters": [
                    {"name": "name", "in": "formData", "type": "string", "required": True, "x-example": "Ada"},
                    {"name": "avatar", "in": "formData", "type": "file"}],
                    "responses": {"204": {"description": "OK"}}}}}}
        result = parse_document(document)
        self.assertEqual(result["base_url"], "https://bank.example/v2")
        self.assertIn("Key", result["security_schemes"])
        body, form = result["endpoints"]
        self.assertEqual(body["response_fields"], ["account_id"])
        self.assertEqual(body["parameters"], [])
        self.assertTrue(body["request_body"]["required"])
        schema = form["request_body"]["content"]["multipart/form-data"]["schema"]
        self.assertEqual(schema["required"], ["name"])
        self.assertEqual(schema["properties"]["name"]["example"], "Ada")
        self.assertEqual(schema["properties"]["avatar"], {"type": "string", "format": "binary"})

    def test_relative_and_operation_servers(self):
        document = openapi()
        document["servers"] = [{"url": "/v1"}]
        document["paths"] = {"/accounts": {"servers": [{"url": "https://other.example/v2"}],
            "get": {"responses": {"200": {"description": "OK"}}}}}
        result = parse_document(document, "https://spec.example/api.yaml")
        self.assertEqual(result["base_url"], "https://spec.example/v1")
        self.assertEqual(result["endpoints"][0]["base_url"], "https://other.example/v2")

    def test_compositions_arrays_and_multiple_responses(self):
        document = openapi()
        document["paths"] = {"/a": {"get": {"responses": {
            "200": {"description": "OK", "content": {"application/json": {"schema": {"type": "array", "items": {
                "allOf": [{"type": "object", "properties": {"id": {"type": "string"}}},
                          {"type": "object", "properties": {"name": {"type": "string"}}}]}}}}},
            "400": {"description": "Bad", "content": {"application/json": {"schema": {
                "type": "object", "properties": {"error": {"type": "string"}}}}}}}}}}
        self.assertEqual(parse_document(document)["endpoints"][0]["response_fields"], ["[].id", "[].name"])

    def test_local_pointer_escaping(self):
        document = openapi()
        document["components"] = {"schemas": {"a~b": {"type": "object", "properties": {"id": {"type": "string"}}}}}
        document["paths"] = {"/a": {"get": {"responses": {"200": {"description": "OK", "content": {
            "application/json": {"schema": {"$ref": "#/components/schemas/a~0b"}}}}}}}}
        self.assertEqual(parse_document(document)["endpoints"][0]["response_fields"], ["id"])

    def test_openapi31_local_schema_anchor(self):
        document = openapi("3.1.0")
        document["components"] = {"schemas": {"Account": {"$anchor": "account", "type": "object",
            "properties": {"account_id": {"type": "string"}}}}}
        document["paths"] = {"/a": {"get": {"responses": {"200": {"description": "OK", "content": {
            "application/json": {"schema": {"$ref": "#account"}}}}}}}}
        self.assertEqual(parse_document(document)["endpoints"][0]["response_fields"], ["account_id"])

    def test_invalid_openapi_really_validated(self):
        document = openapi()
        del document["info"]
        with self.assertRaisesRegex(ValueError, "Invalid OpenAPI"):
            parse_document(document)
        with patch("openapi_spec_validator.validate", side_effect=ValueError("validator ran")) as validate:
            with self.assertRaisesRegex(ValueError, "validator ran"):
                parse_document(openapi())
            validate.assert_called_once()

    def test_duplicate_operation_ids(self):
        document = openapi()
        document["paths"] = {path: {"get": {"operationId": "duplicate", "responses": {
            "200": {"description": "OK"}}}} for path in ("/a", "/b")}
        with self.assertRaises(ValueError):
            parse_document(document)


class PostmanTests(unittest.TestCase):
    def test_nested_variables_auth_query_headers_and_raw_body(self):
        document = collection([{"name": "folder", "variable": [{"key": "tenant", "value": "alpha"}], "item": [
            request({"raw": "{{base}}/accounts/:account_id?ignored=raw", "variable": [{"key": "account_id", "value": "acct-7"}],
                     "query": [{"key": "tenant", "value": "{{tenant}}"}, {"key": "off", "disabled": True}]},
                    method="post", header=[{"key": "Content-Type", "value": "application/json"},
                                           {"key": "X-Trace", "value": "{{unknown}}"}],
                    body={"mode": "raw", "raw": '{"balance": 0, "active": false, "tenant": "{{tenant}}"}'})]}],
            variable=[{"key": "host", "value": "https://bank.example"}, {"key": "base", "value": "{{host}}/v1"}],
            auth={"type": "bearer", "bearer": [{"key": "token", "value": "{{tenant}}-token"}]})
        before = copy.deepcopy(document)
        result = parse_document(document)
        self.assertEqual(document, before)
        self.assertEqual(result["base_url"], "https://bank.example")
        endpoint = result["endpoints"][0]
        self.assertEqual(endpoint["path"], "/v1/accounts/{account_id}")
        self.assertEqual(endpoint["method"], "POST")
        self.assertEqual([p["example"] for p in endpoint["parameters"]], ["acct-7", "alpha", "application/json", "{{unknown}}"])
        self.assertTrue(all(p["required"] for p in endpoint["parameters"]))
        media = endpoint["request_body"]["content"]["application/json"]
        self.assertEqual(media["example"], {"balance": 0, "active": False, "tenant": "alpha"})
        self.assertEqual(media["schema"]["properties"]["active"], {"type": "boolean"})
        auth = next(iter(result["security_schemes"].values()))
        self.assertEqual(auth["scheme"], "bearer")
        self.assertEqual(auth["x-postman-auth"]["bearer"][0]["value"], "alpha-token")

    def test_form_bodies_and_required_values(self):
        for mode, media in (("urlencoded", "application/x-www-form-urlencoded"), ("formdata", "multipart/form-data")):
            body = {"mode": mode, mode: [{"key": "amount", "value": "0"}, {"key": "empty", "value": ""},
                                        {"key": "off", "value": "not present", "disabled": True}]}
            result = parse_document(collection([request(body=body)]))
            normalized = result["endpoints"][0]["request_body"]
            self.assertTrue(normalized["required"])
            self.assertEqual(normalized["content"][media]["schema"]["required"], ["amount", "empty"])
            self.assertEqual(normalized["content"][media]["example"], {"amount": "0", "empty": ""})

    def test_files_plaintext_and_graphql(self):
        for body, media, expected in (
            ({"mode": "file", "file": {"src": "never-read-this"}}, "application/octet-stream", None),
            ({"mode": "raw", "raw": "hello"}, "text/plain", "hello"),
            ({"mode": "graphql", "graphql": {"query": "{ account { id } }", "variables": "{}"}},
             "application/json", {"query": "{ account { id } }", "variables": "{}"}),
        ):
            with self.subTest(body=body):
                content = parse_document(collection([request(body=body)]))["endpoints"][0]["request_body"]["content"][media]
                if expected is not None:
                    self.assertEqual(content["example"], expected)
                else:
                    self.assertEqual(content["schema"], {"type": "string", "format": "binary"})
        body = {"mode": "formdata", "formdata": [{"key": "upload", "type": "file", "src": "not-read"}]}
        content = parse_document(collection([request(body=body)]))["endpoints"][0]["request_body"]["content"]["multipart/form-data"]
        self.assertEqual(content["schema"]["properties"]["upload"], {"type": "string", "format": "binary"})

    def test_auth_inheritance_noauth_and_api_key(self):
        document = collection([{"auth": {"type": "noauth"}, "item": [request()]}, request(),
            request(auth={"type": "apikey", "apikey": [{"key": "key", "value": "X-Key"},
                                                       {"key": "value", "value": "secret"}]})],
            auth={"type": "basic", "basic": [{"key": "username", "value": "demo"}]})
        result = parse_document(document)
        self.assertEqual(result["endpoints"][0]["security"], [])
        self.assertTrue(result["endpoints"][1]["security"])
        self.assertEqual(len(result["security_schemes"]), 2)
        api_key = list(result["security_schemes"].values())[1]
        self.assertEqual((api_key["type"], api_key["name"], api_key["in"]), ("apiKey", "X-Key", "header"))

    def test_raw_url_query_examples_response_fields_and_graph(self):
        first = request()
        first["response"] = [{"code": 201, "body": '{"account_id": "acct-1", "nested": {"name": "Ada"}}'},
                             {"code": 400, "body": '{"error": "bad"}'}]
        second = request("https://bank.example/accounts?account_id=acct%201&empty=&flag&x=a+b")
        result = parse_document(collection([first, second]))
        self.assertEqual(result["endpoints"][0]["response_fields"], ["account_id", "nested", "nested.name"])
        params = result["endpoints"][1]["parameters"]
        self.assertEqual([p.get("example") for p in params], ["acct 1", "", None, "a b"])
        self.assertEqual(result["graph"], [{"source": "postman_0", "target": "postman_1",
                                         "field": "account_id", "parameter": "account_id"}])

    def test_structured_url_and_multiple_origins(self):
        result = parse_document(collection([request({"protocol": "https", "host": ["bank", "example"], "path": ["v1", "accounts"]}),
                                            request("https://other.example/a")]))
        self.assertEqual(result["endpoints"][0]["path"], "/v1/accounts")
        self.assertEqual(result["endpoints"][1]["base_url"], "https://other.example")

    def test_unresolved_and_cyclic_variables_stay_bounded(self):
        document = collection([request(header=[{"key": "X", "value": "{{a}}"}],
            body={"mode": "raw", "raw": '{"id": {{id}}}', "options": {"raw": {"language": "json"}}})],
            variable=[{"key": "a", "value": "{{b}}"}, {"key": "b", "value": "{{a}}"}])
        endpoint = parse_document(document)["endpoints"][0]
        self.assertIn(endpoint["parameters"][0]["example"], ("{{a}}", "{{b}}"))
        self.assertEqual(endpoint["request_body"]["content"]["application/json"]["example"], '{"id": {{id}}}')

    def test_null_auth_inherits_and_typed_defaults(self):
        document = collection([{"auth": None, "item": [request(auth=None,
            body={"mode": "raw", "raw": '{"active": {{enabled}}}', "options": {"raw": {"language": "json"}}})]}],
            variable=[{"key": "enabled", "value": False}], auth={"type": "bearer", "bearer": []})
        result = parse_document(document)
        endpoint = result["endpoints"][0]
        self.assertTrue(endpoint["security"])
        self.assertEqual(endpoint["request_body"]["content"]["application/json"]["example"], {"active": False})

    def test_unresolved_first_origin_does_not_acquire_later_origin(self):
        result = parse_document(collection([request("{{unknown}}/a"), request("https://other.example/a")]))
        self.assertEqual(result["base_url"], "")
        self.assertEqual(result["endpoints"][1]["base_url"], "https://other.example")
        result = parse_document(collection([request({"protocol": "https", "host": ["localhost"], "port": "8443", "path": ["a"]})]))
        self.assertEqual(result["base_url"], "https://localhost:8443")

    def test_postman_alias_cycles_are_rejected(self):
        document = collection()
        document["item"].append(document)
        with self.assertRaisesRegex(ValueError, "cycle"):
            parse_document(document)

    def test_malformed_postman(self):
        documents = [collection(item={}), collection([{}]), collection([{"request": {"method": "GET"}}]),
                     collection([request("ftp://bad.example/a")]), collection([request("https:///missing-host")]),
                     collection([request(header="bad")]), collection([request(body="bad")]),
                     collection([request(body={"mode": "unknown"})]), collection([request(method=5)]),
                     collection([request(body={"mode": "raw", "raw": "not json", "options": {"raw": {"language": "json"}}})]),
                     collection(variable={}), collection([{"item": [], "request": {}}]),
                     collection([request({"host": [1], "path": []})]),
                     collection([request(body={"mode": "raw", "options": []})])]
        for document in documents:
            with self.subTest(document=document), self.assertRaises(ValueError):
                parse_document(document)


class GraphTests(unittest.TestCase):
    def test_exact_names_only_and_no_self_or_header_links(self):
        endpoints = [
            {"operation_id": "create", "response_fields": ["account_id", "owner.id", "id"],
             "parameters": [{"name": "id", "in": "path"}]},
            {"operation_id": "read", "parameters": [{"name": "account_id", "in": "path"},
                {"name": "accountId", "in": "query"}, {"name": "user_id", "in": "query"},
                {"name": "id", "in": "header"}, {"name": "account_id", "in": "query"}]}]
        self.assertEqual(build_graph(endpoints), [{"source": "create", "target": "read",
                         "field": "account_id", "parameter": "account_id"}])

    def test_exact_leaf_and_full_path_matches_keep_ambiguity(self):
        source = {"operation_id": "source", "response_fields": ["data.id", "owner.id", "id", "data.account_id"]}
        target = {"operation_id": "target", "parameters": [
            {"name": name, "in": "query"} for name in ("id", "data.account_id", "accountId", "user_id")]}
        edges = build_graph([source, target])
        self.assertEqual([(e["field"], e["parameter"]) for e in edges], [
            ("data.id", "id"), ("owner.id", "id"), ("id", "id"), ("data.account_id", "data.account_id")])

    def test_required_json_body_names_only_and_no_array_item_guesses(self):
        source = {"operation_id": "source", "response_fields": [
            "data.account_id", "optional", "rows[].id", "[].id"]}
        target = {"operation_id": "target", "parameters": [{"name": "id", "in": "path"}],
            "request_body": {"required": True, "content": {"application/problem+json": {"schema": {
                "type": "object", "required": ["account_id"], "properties": {
                    "account_id": {"type": "string"}, "optional": {"type": "string"}}}}}}}
        self.assertEqual(build_graph([source, target]), [
            {"source": "source", "target": "target", "field": "data.account_id", "parameter": "account_id"}])
        target["request_body"]["content"] = {"multipart/form-data": {"schema": {
            "type": "object", "required": ["account_id"]}}}
        self.assertEqual(build_graph([source, target]), [])

    def test_empty_graph(self):
        self.assertEqual(build_graph([]), [])


if __name__ == "__main__":
    unittest.main()
