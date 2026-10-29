"""Validated, opt-in authorization rules. See README.md for the public format."""

from __future__ import annotations

import copy
import math
import re
import secrets
import uuid
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
import yaml

from ..guardrails import UnsafeRequest
from .verdict import evaluate_differential

__all__ = ["load_rules", "run_rules"]

_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}
_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_TYPES = {"string", "number", "integer", "boolean", "object", "array", "null"}
_MISSING = object()
_TEMPLATE = re.compile(r"\{\{\s*([\w.-]+)\s*\}\}")
_PATH_PARAMETER = re.compile(r"\{([^{}]+)\}")


class _RuleLoader(yaml.SafeLoader):
    pass


def _mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, str) or key in result:
            raise ValueError("YAML mapping keys must be unique strings")
        result[key] = loader.construct_object(value_node, deep=True)
    return result


_RuleLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _json(value, depth=0):
    if depth > 64:
        raise ValueError("JSON values must be acyclic and at most 64 levels deep")
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) is list:
        for item in value:
            _json(item, depth + 1)
        return
    if type(value) is dict and all(type(key) is str for key in value):
        for item in value.values():
            _json(item, depth + 1)
        return
    raise ValueError("Expected a JSON value")


def _keys(value, allowed, required=()):
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise ValueError("Missing or unknown rule fields")


def _text(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Expected a nonempty string")


def _path(value):
    _text(value)
    if (not value.startswith("/") or value.startswith("//")
            or any(char in value for char in "?#\\\r\n")
            or any(part in (".", "..") for part in value.split("/"))):
        raise ValueError("Endpoint paths must be absolute relative paths without traversal")


def _validate_rules(rules):
    if not isinstance(rules, list):
        raise ValueError("Rules must be a list")
    ids = set()
    for rule in rules:
        _keys(rule, {"id", "name", "severity", "owasp_category", "cvss_score",
                     "target_endpoints", "auth_contexts", "assertions", "parameters", "body",
                     "acceptable_status", "leak_detection", "controls", "confirm"},
              {"id", "name", "severity", "owasp_category", "cvss_score", "target_endpoints"})
        differential = "leak_detection" in rule
        if not differential and set(rule) & {"acceptable_status", "controls", "confirm"}:
            raise ValueError("Differential fields require leak_detection")
        if not differential and "assertions" not in rule:
            raise ValueError("Legacy rules require assertions")
        if differential and "assertions" in rule:
            raise ValueError("Differential rules must not mix assertions with leak_detection")
        for name in ("id", "name", "owasp_category"):
            _text(rule[name])
        if rule["id"] in ids:
            raise ValueError("Duplicate rule id")
        ids.add(rule["id"])
        if not isinstance(rule["severity"], str) or rule["severity"].lower() not in _SEVERITIES:
            raise ValueError("Invalid severity")
        score = rule["cvss_score"]
        if type(score) not in (int, float) or not 0 <= score <= 10:
            raise ValueError("CVSS score must be a number between 0 and 10")
        targets = rule["target_endpoints"]
        if not isinstance(targets, list) or not targets:
            raise ValueError("target_endpoints must be a nonempty list")
        for target in targets:
            _keys(target, {"path", "method"}, {"path", "method"})
            _path(target["path"])
            if not isinstance(target["method"], str) or target["method"] not in _METHODS:
                raise ValueError("Methods must be uppercase HTTP methods")
        auth = rule.get("auth_contexts", {})
        _keys(auth, {"primary", "forbidden"})
        for name in auth.values():
            _text(name)
        params = rule.get("parameters", {})
        _keys(params, {"path", "query", "header"})
        for values in params.values():
            if not isinstance(values, dict) or not all(isinstance(k, str) and k for k in values):
                raise ValueError("Parameter values must be name-to-value mappings")
            _json(values)
        header_names = params.get("header", {})
        if len({name.lower() for name in header_names}) != len(header_names):
            raise ValueError("Duplicate rule parameter header")
        if "body" in rule:
            _json(rule["body"])
        assertions = rule.get("assertions", [])
        if not differential and (not isinstance(assertions, list) or not assertions):
            raise ValueError("assertions must be a nonempty list")
        for assertion in assertions:
            if not isinstance(assertion, dict):
                raise ValueError("Assertions must be mappings")
            kind = assertion.get("type")
            if kind == "status_code":
                _keys(assertion, {"type", "expected"}, {"type", "expected"})
                if type(assertion["expected"]) is not int or not 100 <= assertion["expected"] <= 599:
                    raise ValueError("Expected status_code must be an integer from 100 to 599")
            elif kind == "header":
                _keys(assertion, {"type", "name", "expected"}, {"type", "name", "expected"})
                _text(assertion["name"])
                if not isinstance(assertion["expected"], str):
                    raise ValueError("Expected header must be a string")
            elif kind == "body":
                _keys(assertion, {"type", "path", "expected", "exists", "value_type"}, {"type", "path"})
                if not isinstance(assertion["path"], str):
                    raise ValueError("Body path must be a string")
                if not set(assertion) & {"expected", "exists", "value_type"}:
                    raise ValueError("Body assertion needs expected, exists or value_type")
                if "exists" in assertion and type(assertion["exists"]) is not bool:
                    raise ValueError("exists must be boolean")
                if "value_type" in assertion and (not isinstance(assertion["value_type"], str)
                                                 or assertion["value_type"] not in _TYPES):
                    raise ValueError("Invalid body value_type")
                if assertion.get("exists") is False and set(assertion) & {"expected", "value_type"}:
                    raise ValueError("exists: false cannot check a value")
            else:
                raise ValueError("Unknown assertion type")
            if "expected" in assertion:
                _json(assertion["expected"])
        if differential:
            acceptable = rule.get("acceptable_status", [401, 403, 404])
            if (not isinstance(acceptable, list) or not acceptable
                    or any(type(status) is not int or not 400 <= status <= 499 or status == 429 for status in acceptable)
                    or len(set(acceptable)) != len(acceptable)):
                raise ValueError("acceptable_status must be a unique nonempty list of HTTP status integers")
            leak = rule["leak_detection"]
            _keys(leak, {"canaries", "min_unique_leaf_values", "ignore_fields"})
            canaries = leak.get("canaries", [])
            if (not isinstance(canaries, list) or any(not isinstance(value, str) or not value.strip() for value in canaries)
                    or len(set(canaries)) != len(canaries)):
                raise ValueError("leak_detection.canaries must be unique nonempty strings")
            minimum = leak.get("min_unique_leaf_values", 2)
            if type(minimum) is not int or minimum < 1:
                raise ValueError("leak_detection.min_unique_leaf_values must be a positive integer")
            ignore = leak.get("ignore_fields", [])
            if (not isinstance(ignore, list) or any(not isinstance(value, str) or not value
                                                   or not re.fullmatch(r"[\w-]+(?:\.[\w-]+)*", value) for value in ignore)
                    or len(set(ignore)) != len(ignore)):
                raise ValueError("leak_detection.ignore_fields must be unique string paths")
            controls = rule.get("controls", {})
            _keys(controls, {"nonexistent_object", "unauthenticated"})
            if any(type(value) is not bool for value in controls.values()):
                raise ValueError("controls values must be booleans")
            confirm = rule.get("confirm", 2)
            if type(confirm) is not int or not 0 <= confirm <= 100:
                raise ValueError("confirm must be an integer between 0 and 100")
            if set(auth) != {"primary", "forbidden"} or auth["primary"] == auth["forbidden"]:
                raise ValueError("Differential rules require distinct primary and forbidden contexts")


def load_rules(paths: Iterable[str]) -> list[dict[str, Any]]:
    """Load UTF-8 YAML files; raise ValueError on any invalid/duplicate rule."""
    if isinstance(paths, (str, bytes)):
        raise ValueError("paths must be an iterable of file names")
    rules = []
    for path in paths:
        try:
            with Path(path).open(encoding="utf-8") as stream:
                document = yaml.load(stream, Loader=_RuleLoader)
        except yaml.YAMLError:
            raise ValueError("Malformed rule YAML") from None
        if isinstance(document, dict):
            if "rules" in document:
                _keys(document, {"rules"}, {"rules"})
                document = document["rules"]
            else:
                document = [document]
        if not isinstance(document, list):
            raise ValueError("Rule file must contain a rule, a list, or a rules mapping")
        rules.extend(document)
    _validate_rules(rules)
    for rule in rules:
        rule["severity"] = rule["severity"].lower()
    return rules


def _lookup(values, path) -> Any:
    if isinstance(values, dict) and path in values:
        return values[path]
    value = values
    if not path:
        return value
    for part in path.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            return _MISSING
    return value


class _Stop(Exception):
    def __init__(self, message, status="error", reason=None):
        self.message = message
        self.status = status
        self.reason = reason


def _expand(value, variables) -> Any:
    if isinstance(value, str):
        match = _TEMPLATE.fullmatch(value)
        if match:
            found = _lookup(variables, match[1])
            if found is _MISSING:
                raise _Stop("Unresolved variable placeholder.")
            return copy.deepcopy(found)

        def replace(match):
            found = _lookup(variables, match[1])
            if found is _MISSING or isinstance(found, (dict, list)) or found is None:
                raise _Stop("Unresolved or nonscalar variable placeholder.")
            return str(found)

        expanded = _TEMPLATE.sub(replace, value)
        if "{{" in expanded or "}}" in expanded:
            raise _Stop("Malformed variable placeholder.")
        return expanded
    if isinstance(value, dict):
        return {k: _expand(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v, variables) for v in value]
    return value


def _field(payload, field):
    if "[]" in field:
        return _MISSING
    if "." in field:
        return _lookup(payload, field)
    # A bare graph field may be wrapped in a response envelope; ambiguity fails closed.
    found = []

    def visit(node, depth=0):
        if depth > 64:
            return
        if isinstance(node, dict):
            for key, item in node.items():
                if key == field:
                    found.append(item)
                else:
                    visit(item, depth + 1)


    visit(payload)
    return found[0] if len(found) == 1 else _MISSING


def _matches_type(value, kind):
    return {"null": value is None, "boolean": type(value) is bool,
            "integer": type(value) is int, "number": type(value) in (int, float),
            "string": isinstance(value, str), "object": isinstance(value, dict),
            "array": isinstance(value, list)}[kind]


def _equal(left, right):
    if type(left) is bool or type(right) is bool:
        return type(left) is type(right) and left == right
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(_equal(left[k], right[k]) for k in left)
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(_equal(a, b) for a, b in zip(left, right))
    return left == right


class _Runtime:
    def __init__(self, inventory, client, contexts, variables):
        self.inventory = inventory
        self.client = client
        self.contexts = contexts
        self.variables = variables
        self.stores = {}
        self.operations = {}
        for endpoint in inventory["endpoints"]:
            op = endpoint.get("operation_id")
            if op:
                if op in self.operations:
                    raise ValueError("Duplicate operation_id in inventory")
                self.operations[op] = endpoint

    def headers(self, context):
        if context is None:
            return {}
        if context not in self.contexts:
            raise _Stop("Named authentication context is unavailable.")
        return dict(self.contexts[context])

    async def request(self, endpoint, inputs, context, timeout_is_inconclusive=False):
        headers = dict(inputs["headers"])
        headers.update({key.lower(): value for key, value in self.headers(context).items()})
        # An explicit empty Cookie header disables HTTPX's shared response cookie jar.
        headers.setdefault("cookie", "")
        for name in inputs["required_headers"]:
            if not headers.get(name):
                raise _Stop("Unresolved required header parameter.")
        kwargs = {"params": copy.deepcopy(inputs["query"]), "headers": headers,
                  "follow_redirects": False, "auth": None}
        if inputs["body"] is not _MISSING:
            kwargs["json"] = copy.deepcopy(inputs["body"])
        try:
            return await self.client.request(endpoint["method"], inputs["url"], **kwargs)
        except UnsafeRequest:
            raise _Stop("Request blocked by the safety guard.", "skipped", "safety_blocked") from None
        except httpx.TimeoutException:
            if timeout_is_inconclusive:
                raise _Stop("HTTP request timed out.", "inconclusive", "timeout") from None
            raise _Stop("HTTP request timed out.", "error", "timeout") from None
        except Exception:
            raise _Stop("HTTP request failed.", "error", "execution_error") from None

    def remember(self, endpoint, response, context):
        if context is None or not 200 <= response.status_code < 300:
            return
        try:
            payload = response.json()
            _json(payload)
        except (ValueError, TypeError, RecursionError):
            return
        if endpoint.get("operation_id"):
            self.stores.setdefault(context, {})[endpoint["operation_id"]] = payload

    async def value(self, name, endpoint, rule, context, stack, budget):
        value = _lookup(self.variables, name)
        if value is not _MISSING:
            return value
        edges = [edge for edge in self.inventory.get("graph", [])
                 if edge["target"] == endpoint.get("operation_id") and edge["parameter"] == name]
        if not edges or context is None:
            return _MISSING
        if len(edges) != 1:
            raise _Stop("Ambiguous dependency for required input.")
        edge = edges[0]
        source = edge["source"]
        store = self.stores.setdefault(context, {})
        if source not in store:
            dependency = self.operations.get(source)
            if dependency is None:
                raise _Stop("Dependency endpoint is unavailable.")
            if source in stack or len(stack) >= 16 or budget[0] >= 32:
                raise _Stop("Dependency cycle or execution limit reached.")
            budget[0] += 1
            inputs = await self.inputs(dependency, rule, context, stack + (source,), budget, dependency=True)
            response = await self.request(dependency, inputs, context)
            if not 200 <= response.status_code < 300:
                raise _Stop("Dependency did not return a successful baseline.")
            self.remember(dependency, response, context)
        return _field(store.get(source, {}), edge["field"])

    async def body(self, schema, value, endpoint, rule, context, stack, budget, prefix="body"):
        if (not isinstance(schema, dict) or any(key in schema for key in
                ("$ref", "$dynamicRef", "$recursiveRef", "allOf", "anyOf", "oneOf", "not", "if", "then", "else"))):
            raise _Stop("Required request schema is unresolved.")
        if value is _MISSING and (schema.get("type") == "object" or "properties" in schema):
            value = {}
        if value is _MISSING or value is None:
            if value is None and (schema.get("nullable") or schema.get("type") == "null"):
                return value
            raise _Stop("Unresolved required body input.")
        kind = schema.get("type")
        if ("properties" in schema or "required" in schema) and not isinstance(value, dict):
            raise _Stop("Required request body properties need an object.")
        if kind is not None and (not isinstance(kind, str) or kind not in _TYPES):
            raise _Stop("Unsupported request body schema type.")
        if kind in _TYPES and not _matches_type(value, kind):
            raise _Stop("Request body does not match its schema type.")
        if isinstance(value, dict):
            value = copy.deepcopy(value)
            properties = schema.get("properties", {})
            for name in schema.get("required", []):
                child = value.get(name, _MISSING)
                if child is _MISSING:
                    child = _lookup(self.variables, prefix + "." + name)
                if child is _MISSING:
                    child = await self.value(name, endpoint, rule, context, stack, budget)
                value[name] = await self.body(properties.get(name, {}), child, endpoint, rule,
                                              context, stack, budget, prefix + "." + name)
            for name in value.keys() - set(schema.get("required", [])):
                if name in properties:
                    value[name] = await self.body(properties[name], value[name], endpoint, rule,
                                                  context, stack, budget, prefix + "." + name)
        if isinstance(value, list) and "items" in schema:
            value = [await self.body(schema["items"], item, endpoint, rule, context, stack, budget,
                                     prefix + "." + str(index)) for index, item in enumerate(value)]
        return value

    async def inputs(self, endpoint, rule, context, stack, budget, dependency=False):
        if endpoint.get("base_url", self.inventory["base_url"]) != self.inventory["base_url"]:
            raise _Stop("Endpoint base_url differs from inventory base_url; explicit override required.")
        path = endpoint["path"]
        try:
            _path(path)
        except ValueError:
            raise _Stop("Invalid inventory endpoint path.") from None
        params = _expand(rule.get("parameters", {}), self.variables)
        params["header"] = {k.lower(): v for k, v in params.get("header", {}).items()}
        # Only declared inputs are forwarded to dependencies, never the target's body.
        values = {location: {} if dependency else dict(params.get(location, {}))
                  for location in ("path", "query", "header")}
        required_headers = set()
        auth_headers = {key.lower(): value for key, value in self.headers(context).items()}
        declarations = list(endpoint.get("parameters", []))
        declared_paths = {p["name"] for p in declarations if p["in"] == "path"}
        declarations.extend({"name": name, "in": "path", "required": True}
                            for name in _PATH_PARAMETER.findall(path) if name not in declared_paths)
        for parameter in declarations:
            name, location = parameter["name"], parameter["in"]
            required = parameter.get("required", False) or location == "path"
            if location not in values:
                if required:
                    raise _Stop("Unsupported required parameter location.")
                continue
            if location == "header":
                if required:
                    required_headers.add(name.lower())
                if name.lower() in auth_headers:
                    continue
                if name.lower() in ("authorization", "proxy-authorization", "cookie"):
                    if required:
                        raise _Stop("Required authentication header needs a named context.")
                    continue
            key = name.lower() if location == "header" else name
            value = params.get(location, {}).get(key, _MISSING)
            if value is _MISSING:
                value = _lookup(self.variables, location + "." + name)
            if value is _MISSING:
                # Optional inputs never cause dependency requests.
                if required:
                    value = await self.value(name, endpoint, rule, context, stack, budget)
                else:
                    value = _lookup(self.variables, name)
            if value is _MISSING or (required and value is None):
                if required:
                    raise _Stop("Unresolved required request parameter.")
                continue
            values[location][key] = value
        context_headers = {name.lower() for context_name in rule.get("auth_contexts", {}).values()
                           for name in self.headers(context_name)}
        if context_headers & values["header"].keys():
            raise _Stop("Context headers cannot be shared rule parameters.")
        if any(name.lower() in ("authorization", "proxy-authorization", "cookie", "host")
               for name in values["header"]):
            raise _Stop("Authentication and Host headers cannot be shared rule parameters.")
        for name, value in values["header"].items():
            if (not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                    or not isinstance(value, (str, int, float, bool))
                    or any(char in str(value) for char in "\r\n")):
                raise _Stop("Invalid request header parameter.")

        def substitute(match):
            value = values["path"].get(match[1], _MISSING)
            if value is _MISSING or value is None or isinstance(value, (dict, list)):
                raise _Stop("Unresolved or nonscalar path parameter.")
            text = str(value)
            if not text or text in (".", ".."):
                raise _Stop("Invalid path parameter.")
            return quote(text, safe="")

        path = _PATH_PARAMETER.sub(substitute, path)
        if "{" in path or "}" in path:
            raise _Stop("Unresolved path placeholder.")
        base = self.inventory["base_url"].rstrip("/")
        body = _MISSING if dependency else _expand(rule.get("body", _MISSING), self.variables)
        request_body = endpoint.get("request_body") or {}
        if body is _MISSING:
            body = _lookup(self.variables, "body")
        if request_body:
            if "$ref" in request_body:
                raise _Stop("Request body reference is unresolved.")
            content = request_body.get("content", {})
            media = next((v for k, v in content.items()
                          if k == "application/json" or k.endswith("+json")), None)
            if request_body.get("required") or body is not _MISSING:
                if media is None or "$ref" in request_body:
                    raise _Stop("Required request body is not a resolved JSON schema.")
                body = await self.body(media.get("schema", {}), body, endpoint, rule, context, stack, budget)
        return {"url": base + path, "query": values["query"],
                "headers": {k.lower(): str(v) for k, v in values["header"].items()},
                "required_headers": required_headers, "body": body,
                "path_values": copy.deepcopy(values["path"])}


def _assertions(response, assertions, variables):
    details = []
    payload = _MISSING
    parsed = False
    for index, assertion in enumerate(assertions):
        kind = assertion["type"]
        expected = _expand(assertion.get("expected", _MISSING), variables)
        if kind == "status_code":
            passed = response.status_code == expected
        elif kind == "header":
            headers = {k.lower(): v for k, v in response.headers.items()}
            passed = headers.get(assertion["name"].lower(), _MISSING) == expected
        else:
            if not parsed:
                try:
                    payload = response.json()
                except (ValueError, TypeError):
                    payload = _MISSING
                parsed = True
            value = _lookup(payload, assertion["path"]) if payload is not _MISSING else _MISSING
            exists = value is not _MISSING
            passed = payload is not _MISSING
            if "exists" in assertion:
                passed = passed and exists == assertion["exists"]
            if "expected" in assertion:
                passed = passed and exists and _equal(value, expected)
            if "value_type" in assertion:
                passed = passed and exists and _matches_type(value, assertion["value_type"])
        details.append({"index": index, "type": kind, "passed": bool(passed)})
    return details


def _response_record(response):
    result = {"status": response.status_code}
    try:
        body = response.json()
        _json(body)
    except (ValueError, TypeError, RecursionError):
        return result
    result["body"] = body
    return result


def _differential_config(rule, variables):
    leak = rule["leak_detection"]
    canaries = _expand(leak.get("canaries", []), variables)
    if any(isinstance(value, (dict, list)) for value in canaries):
        raise _Stop("Canary values must resolve to scalar JSON values.", reason="invalid_canary")
    return {"acceptable_status": rule.get("acceptable_status", [401, 403, 404]),
            "canaries": canaries, "min_unique_leaf_values": leak.get("min_unique_leaf_values", 2),
            "ignore_fields": leak.get("ignore_fields", [])}


def _nonexistent_value(schema, current):
    """Generate a schema-compatible candidate, never claim it is known absent."""
    if not isinstance(schema, dict) or "enum" in schema or "const" in schema:
        return _MISSING
    kind = schema.get("type")
    if kind == "integer":
        ceiling = 2**63 - 1 if schema.get("format") == "int64" else 2**31 - 1
        low = max(0, math.ceil(schema.get("minimum", 0)))
        high = min(ceiling, math.floor(schema.get("maximum", ceiling)))
        if isinstance(schema.get("exclusiveMinimum"), bool):
            low += int(schema["exclusiveMinimum"])
        elif "exclusiveMinimum" in schema:
            low = max(low, math.floor(schema["exclusiveMinimum"]) + 1)
        if isinstance(schema.get("exclusiveMaximum"), bool):
            high -= int(schema["exclusiveMaximum"])
        elif "exclusiveMaximum" in schema:
            high = min(high, math.ceil(schema["exclusiveMaximum"]) - 1)
        if high <= low or "multipleOf" in schema:
            return _MISSING
        for _ in range(8):
            candidate = low + secrets.randbelow(high - low + 1)
            if str(candidate) != str(current):
                return candidate
        return _MISSING
    if kind != "string":
        return _MISSING
    random_id = str(uuid.uuid4())
    candidates = [random_id] if schema.get("format") == "uuid" else ["ledgerprobe-" + random_id, random_id.replace("-", "")]
    # Preserve an existing ID's separators/prefix and length to cover common
    # usr_*, numeric-string and fixed-width patterns without synthesizing regexes.
    if isinstance(current, str) and schema.get("format") != "uuid":
        for _ in range(8):
            candidates.append("".join(str(secrets.randbelow(10)) if char.isdigit()
                                      else secrets.choice("abcdefghijklmnopqrstuvwxyz") if char.islower()
                                      else secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") if char.isupper()
                                      else char for char in current))
            if "_" in current:
                prefix, _, tail = current.rpartition("_")
                candidates.append(prefix + "_" + secrets.token_hex(max(1, len(tail)))[:len(tail)])
    pattern = schema.get("pattern")
    for candidate in candidates:
        if (candidate == str(current) or not schema.get("minLength", 0) <= len(candidate) <= schema.get("maxLength", 4096)):
            continue
        if schema.get("format") not in (None, "uuid"):
            continue
        try:
            if pattern is None or re.search(pattern, candidate):
                return candidate
        except re.error:
            return _MISSING
    return _MISSING


def _nonexistent_inputs(endpoint, inputs, base_url):
    parameters = [p for p in endpoint.get("parameters", []) if p.get("in") in {"path", "query"}
                  and (p.get("name") == "id" or p.get("name", "").endswith("_id"))]
    if not parameters:
        parameters = [p for p in endpoint.get("parameters", []) if p.get("in") == "path"]
    # Nested resource IDs are ambiguous: never replace a tenant ID by guessing.
    if len(parameters) != 1:
        return None
    parameter = parameters[0]
    name, location = parameter["name"], parameter["in"]
    values = inputs["path_values"] if location == "path" else inputs["query"]
    generated = _nonexistent_value(parameter.get("schema"), values.get(name))
    if generated is _MISSING:
        return None
    copied = dict(inputs)
    if location == "query":
        copied["query"] = {**inputs["query"], name: generated}
    else:
        path_values = {**inputs["path_values"], name: generated}
        path = _PATH_PARAMETER.sub(lambda match: quote(str(path_values[match[1]]), safe=""), endpoint["path"])
        copied["url"] = base_url.rstrip("/") + path
    return copied


async def _differential_result(runtime, endpoint, inputs, forbidden, rule, baseline, comparison):
    async def observe(request_inputs, context):
        try:
            response = await runtime.request(endpoint, request_inputs, context, timeout_is_inconclusive=True)
            return _response_record(response)
        except _Stop as exc:
            if exc.reason == "timeout":
                return {"error": "timeout"}
            raise

    baseline_record = _response_record(baseline)
    forbidden_record = await observe(inputs, forbidden)
    evaluate = {"baseline": baseline_record, "forbidden": forbidden_record, **comparison}
    # Denials, overload and failed/unsupported responses need no extra traffic.
    if not 200 <= forbidden_record.get("status", 0) < 300:
        return evaluate_differential(**evaluate)
    controls = {"nonexistent_object": True, "unauthenticated": True, **rule.get("controls", {})}
    nonexistent = unauthenticated = None
    skipped = False
    if controls["nonexistent_object"]:
        control_inputs = _nonexistent_inputs(endpoint, inputs, runtime.inventory["base_url"])
        skipped = control_inputs is None
        if control_inputs is not None:
            nonexistent = await observe(control_inputs, forbidden)
    if controls["unauthenticated"]:
        # Context credentials are never copied into shared headers; empty Cookie
        # plus auth=None also prevents HTTPX cookie-jar and default-auth reuse.
        anonymous = {**inputs, "required_headers": set()}
        unauthenticated = await observe(anonymous, None)
    evaluate.update(nonexistent=nonexistent, unauthenticated=unauthenticated, nonexistent_skipped=skipped)
    provisional = evaluate_differential(confirm=0, **evaluate)
    confirmations = []
    if provisional["status"] == "failed":
        for _ in range(rule.get("confirm", 2)):
            observation = await observe(inputs, forbidden)
            confirmations.append(observation)
            # Stop on overload/timeouts; do not hammer an unhealthy target.
            if observation.get("error") or observation.get("status") == 429 or observation.get("status", 0) >= 500:
                break
    return evaluate_differential(confirm=rule.get("confirm", 2), confirm_responses=confirmations, **evaluate)


async def run_rules(inventory: dict, rules: list[dict], client,
                    contexts: dict | None = None, variables: dict | None = None) -> list[dict]:
    """Execute selected rules through an async guarded client; return redacted results.

    Invalid rules/context/variable configuration raises ValueError before any HTTP.
    Per-endpoint resolution, transport and baseline failures become result records.
    """
    _validate_rules(rules)
    contexts = {} if contexts is None else contexts
    variables = {} if variables is None else variables
    if not isinstance(contexts, dict) or not isinstance(variables, dict):
        raise ValueError("contexts and variables must be mappings")
    _json(variables)
    for name, headers in contexts.items():
        _text(name)
        if not isinstance(headers, dict):
            raise ValueError("Contexts must contain header mappings")
        for key, value in headers.items():
            _text(key)
            if (not isinstance(value, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key)
                    or any(char in value for char in "\r\n") or key.lower() == "host"):
                raise ValueError("Invalid authentication context header")
        if len({key.lower() for key in headers}) != len(headers):
            raise ValueError("Duplicate authentication context header")
    base = urlsplit(inventory["base_url"])
    if (base.scheme not in ("http", "https") or not base.netloc or base.username is not None
            or base.password is not None or base.query or base.fragment):
        raise ValueError("Inventory base_url must be an HTTP(S) URL without credentials/query/fragment")
    runtime = _Runtime(inventory, client, contexts, variables)
    results = []
    for rule in rules:
        for target in rule["target_endpoints"]:
            result = {key: rule[key] for key in ("name", "severity", "owasp_category", "cvss_score")}
            result.update(rule_id=rule["id"], severity=rule["severity"].lower(),
                          path=target["path"], method=target["method"])
            try:
                matches = [e for e in inventory["endpoints"]
                           if e["path"] == target["path"] and e["method"] == target["method"]]
                if not matches:
                    raise _Stop("Selected endpoint is absent from inventory.", "skipped", "endpoint_absent")
                if len(matches) != 1:
                    raise _Stop("Selected endpoint is ambiguous in inventory.")
                endpoint = matches[0]
                differential = "leak_detection" in rule
                comparison = _differential_config(rule, variables) if differential else None
                auth = rule.get("auth_contexts", {})
                primary, forbidden = auth.get("primary"), auth.get("forbidden")
                if differential and (primary is None or forbidden is None):
                    raise _Stop("Differential rules require primary and forbidden contexts.", "error", "invalid_rule")
                runtime.headers(primary)
                runtime.headers(forbidden)
                op = endpoint.get("operation_id")
                inputs = await runtime.inputs(endpoint, rule, primary, (op,) if op else (), [0])
                # Check forbidden required headers before sending even the baseline.
                forbidden_headers = dict(inputs["headers"])
                forbidden_headers.update({k.lower(): v for k, v in runtime.headers(forbidden).items()})
                if any(not forbidden_headers.get(k) for k in inputs["required_headers"]):
                    raise _Stop("Unresolved required forbidden-context header.", "error", "execution_error")
                if primary is not None:
                    try:
                        baseline = await runtime.request(endpoint, inputs, primary)
                    except _Stop as exc:
                        if differential and exc.reason == "timeout":
                            raise _Stop("Primary baseline timed out.", reason="baseline_timeout") from None
                        raise
                    if not 200 <= baseline.status_code < 300:
                        raise _Stop("Primary baseline did not return 2xx; forbidden request not sent.",
                                    "error", "baseline_not_2xx")
                    runtime.remember(endpoint, baseline, primary)
                if differential:
                    result.update(await _differential_result(runtime, endpoint, inputs, forbidden,
                                                             rule, baseline, comparison))
                else:
                    response = await runtime.request(endpoint, inputs, forbidden)
                    details = _assertions(response, rule["assertions"], variables)
                    passed = all(detail["passed"] for detail in details)
                    result.update(status="passed" if passed else "failed", assertions=details,
                                  message="All assertions passed." if passed else "One or more assertions failed.")
                    if not passed:
                        result.update(reason="assertion_failed", verdict="FAIL")
            except _Stop as exc:
                result.update(status=exc.status, message=exc.message,
                              verdict={"error": "ERROR", "skipped": "SKIPPED", "inconclusive": "INCONCLUSIVE"}[exc.status])
                result["reason"] = exc.reason or "execution_error"
            except Exception:
                result.update(status="error", verdict="ERROR", message="Rule execution could not be completed.",
                              reason="execution_error")
            results.append(result)
    return results
