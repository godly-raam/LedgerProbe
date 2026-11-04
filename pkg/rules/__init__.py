"""Validated, opt-in authorization rules. See README.md for the public format."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
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

from ..auth import AuthError
from ..guardrails import UnsafeRequest
from ..cvss import parse_vector, resolve_cvss
from ..fingerprints import check_type, fingerprint, identity_roles
from ..cwe import cwe_for
from .verdict import _typed, _values, evaluate_differential, evaluate_mutation, evaluate_race, evaluate_scoped

__all__ = ["load_rules", "run_rules"]

_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
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


def _request_spec(value):
    """Validate a restore/verify request without assuming an OpenAPI operation."""
    _keys(value, {"method", "path", "auth", "body", "query"}, {"method", "path"})
    if not isinstance(value["method"], str) or value["method"] not in _METHODS:
        raise ValueError("Mutation request methods must be uppercase HTTP methods")
    _path(value["path"])
    auth = value.get("auth", "primary")
    if not isinstance(auth, str) or not auth:
        raise ValueError("Mutation request auth must be a nonempty string")
    if "body" in value:
        _json(value["body"])
    query = value.get("query", {})
    if not isinstance(query, dict) or not all(isinstance(key, str) and key for key in query):
        raise ValueError("Mutation request query must be a string mapping")
    _json(query)


def _body_assertion(value):
    _keys(value, {"path", "expected", "exists", "value_type"}, {"path"})
    if not isinstance(value["path"], str):
        raise ValueError("Verification body path must be a string")
    if not set(value) & {"expected", "exists", "value_type"}:
        raise ValueError("Verification body needs expected, exists or value_type")
    if "exists" in value and type(value["exists"]) is not bool:
        raise ValueError("Verification exists must be boolean")
    if "value_type" in value and (not isinstance(value["value_type"], str)
                                  or value["value_type"] not in _TYPES):
        raise ValueError("Invalid verification body value_type")
    if value.get("exists") is False and set(value) & {"expected", "value_type"}:
        raise ValueError("Verification exists: false cannot check a value")
    if "expected" in value:
        _json(value["expected"])


def _verify_spec(value):
    _keys(value, {"mode", "readback", "request", "snapshot", "expected_status",
                 "response_body", "fields"}, {"mode"})
    mode = value["mode"]
    if mode not in {"marker", "probe", "state_diff"}:
        raise ValueError("verify.mode must be marker, probe or state_diff")
    if mode == "marker":
        if "readback" not in value:
            raise ValueError("marker verification requires readback")
        _request_spec(value["readback"])
        extra = set(value) - {"mode", "readback"}
        if extra:
            raise ValueError("marker verification has unknown fields")
    elif mode == "probe":
        if "request" not in value or "expected_status" not in value:
            raise ValueError("probe verification requires request and expected_status")
        _request_spec(value["request"])
        if type(value["expected_status"]) is not int or not 100 <= value["expected_status"] <= 599:
            raise ValueError("probe expected_status must be 100..599")
        if "response_body" in value:
            _body_assertion(value["response_body"])
        extra = set(value) - {"mode", "request", "expected_status", "response_body"}
        if extra:
            raise ValueError("probe verification has unknown fields")
    else:
        if "snapshot" not in value or "fields" not in value:
            raise ValueError("state_diff verification requires snapshot and fields")
        _request_spec(value["snapshot"])
        fields = value["fields"]
        if (not isinstance(fields, list) or not fields
                or any(not isinstance(field, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", field)
                       for field in fields)
                or len(set(fields)) != len(fields)):
            raise ValueError("state_diff fields must be unique JSON paths")
        extra = set(value) - {"mode", "snapshot", "fields"}
        if extra:
            raise ValueError("state_diff verification has unknown fields")


def _race_spec(value):
    _keys(value, {"requests", "rounds", "sync", "identity", "reset", "success_status",
                  "idempotency", "max_spread_ms", "invariant"},
          {"identity", "reset", "invariant"})
    requests = value.get("requests", 10)
    if type(requests) is not int or not 1 <= requests <= 50:
        raise ValueError("race.requests must be an integer from 1 to 50")
    rounds = value.get("rounds", 5)
    if type(rounds) is not int or not 1 <= rounds <= 20:
        raise ValueError("race.rounds must be an integer from 1 to 20")
    if value.get("sync", "last_byte") not in {"last_byte", "h2_single_packet", "burst"}:
        raise ValueError("race.sync must be last_byte, h2_single_packet or burst")
    _text(value["identity"])
    reset = value["reset"]
    if not isinstance(reset, list) or not reset:
        raise ValueError("race.reset must be a nonempty list")
    for request in reset:
        if not isinstance(request, dict):
            raise ValueError("race.reset entries must be mappings")
        _request_spec(request)
    successes = value.get("success_status", [200, 201, 204])
    if (not isinstance(successes, list) or not successes
            or any(type(status) is not int or not 200 <= status < 400 for status in successes)
            or len(set(successes)) != len(successes)):
        raise ValueError("race.success_status must be a unique nonempty list of 2xx/3xx statuses")
    spread = value.get("max_spread_ms", 5)
    if type(spread) not in (int, float) or isinstance(spread, bool) or not math.isfinite(spread) or spread <= 0:
        raise ValueError("race.max_spread_ms must be finite and positive")
    identity = value.get("idempotency")
    if identity is not None:
        _keys(identity, {"header", "mode"}, {"mode"})
        if identity["mode"] not in {"same", "unique", "none"}:
            raise ValueError("race.idempotency.mode must be same, unique or none")
        header = identity.get("header", "Idempotency-Key")
        if not isinstance(header, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", header):
            raise ValueError("race.idempotency.header must be a valid HTTP header name")
        if identity["mode"] != "none" and not header:
            raise ValueError("race.idempotency.header is required for same or unique mode")
    invariant = value["invariant"]
    _keys(invariant, {"max_successes", "ledger"})
    if not set(invariant) & {"max_successes", "ledger"}:
        raise ValueError("race.invariant requires max_successes or ledger")
    if "max_successes" in invariant:
        maximum = invariant["max_successes"]
        if type(maximum) is not int or maximum < 1:
            raise ValueError("race.invariant.max_successes must be a positive integer")
    if "ledger" in invariant:
        ledger = invariant["ledger"]
        _keys(ledger, {"snapshot", "path", "delta_per_success", "max_total_effect"},
              {"snapshot", "path", "delta_per_success", "max_total_effect"})
        _request_spec(ledger["snapshot"])
        if (not isinstance(ledger["path"], str) or not ledger["path"]
                or any(char in ledger["path"] for char in "\r\n")):
            raise ValueError("race.invariant.ledger.path must be a nonempty string")
        for name in ("delta_per_success", "max_total_effect"):
            number = ledger[name]
            if (type(number) not in (int, float) or isinstance(number, bool)
                    or not math.isfinite(number)):
                raise ValueError(f"race.invariant.ledger.{name} must be finite")
        if ledger["max_total_effect"] < 0:
            raise ValueError("race.invariant.ledger.max_total_effect must be nonnegative")
    if identity is not None and identity["mode"] == "unique" and "ledger" not in invariant:
        raise ValueError("unique idempotency requires a ledger invariant")


def _validate_rules(rules, *, require_mutating=True, accept_generated=False):
    if not isinstance(rules, list):
        raise ValueError("Rules must be a list")
    ids = set()
    for rule in rules:
        _keys(rule, {"id", "name", "severity", "owasp_category", "cvss_score", "cvss",
                     "target_endpoints", "auth_contexts", "assertions", "parameters", "body",
                     "acceptable_status", "leak_detection", "controls", "confirm", "pagination",
                     "require_primary_canary", "scope", "require_owner_canary_in_baseline", "spec_check",
                     "mutating", "verify", "restore", "race", "remediation",
                     "generated_from", "review_required", "scope_confidence", "disabled"},
              {"id", "name", "severity", "owasp_category", "cvss_score", "target_endpoints"})
        if "generated_from" in rule and rule["generated_from"] not in {"har", "postman", "mitm"}:
            raise ValueError("generated_from must be har, postman or mitm")
        if "review_required" in rule and type(rule["review_required"]) is not bool:
            raise ValueError("review_required must be boolean")
        if rule.get("review_required") is True and not accept_generated:
            raise ValueError("Generated rules require review; rerun with --accept-generated")
        if "scope_confidence" in rule and rule["scope_confidence"] not in {"high", "medium", "low"}:
            raise ValueError("scope_confidence must be high, medium or low")
        disabled = rule.get("disabled", False)
        if type(disabled) is not bool:
            raise ValueError("disabled must be boolean")
        if "remediation" in rule:
            _text(rule["remediation"])
        differential = "leak_detection" in rule
        mutating = rule.get("mutating", False)
        if type(mutating) is not bool:
            raise ValueError("mutating must be boolean")
        if not differential and not mutating and set(rule) & {"acceptable_status", "controls", "confirm", "pagination",
                                            "require_primary_canary", "scope",
                                            "require_owner_canary_in_baseline"}:
            raise ValueError("Differential fields require leak_detection")
        if "spec_check" in rule and rule["spec_check"] not in {"strict", "warn"}:
            raise ValueError("spec_check must be strict or warn")
        if not differential and not mutating and "assertions" not in rule:
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
        if "cvss" in rule:
            override = rule["cvss"]
            _keys(override, {"vector", "justification"}, {"vector", "justification"})
            if not isinstance(override["vector"], str):
                raise ValueError("cvss.vector must be a string")
            parse_vector(override["vector"])
            _text(override["justification"])
        targets = rule["target_endpoints"]
        if not isinstance(targets, list) or not targets:
            raise ValueError("target_endpoints must be a nonempty list")
        for target in targets:
            _keys(target, {"path", "method"}, {"path", "method"})
            _path(target["path"])
            if not isinstance(target["method"], str) or target["method"] not in _METHODS:
                raise ValueError("Methods must be uppercase HTTP methods")
        if disabled:
            continue
        non_safe = any(target["method"] not in _SAFE_METHODS for target in targets)
        if non_safe and not mutating and require_mutating:
            raise ValueError("Non-safe methods require mutating: true")
        if mutating and not non_safe:
            raise ValueError("mutating: true requires a non-safe method")
        if mutating:
            if "assertions" in rule:
                raise ValueError("Mutating rules must use verify, not assertions")
            if "restore" not in rule:
                raise ValueError("Mutating rules require restore")
            if "verify" in rule:
                _verify_spec(rule["verify"])
            if "race" in rule:
                if "verify" in rule:
                    raise ValueError("Race rules must use race, not verify")
                _race_spec(rule["race"])
            restore = rule["restore"]
            if not isinstance(restore, list) or not restore:
                raise ValueError("restore must be a nonempty list")
            for request in restore:
                if not isinstance(request, dict):
                    raise ValueError("restore entries must be mappings")
                _request_spec(request)
            confirm = rule.get("confirm", 1)
            if type(confirm) is not int or not 0 <= confirm <= 1:
                raise ValueError("Mutating confirm must be 0 or 1")
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
        if not differential and not mutating and (not isinstance(assertions, list) or not assertions):
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
        if differential or mutating:
            acceptable = rule.get("acceptable_status", [401, 403, 404])
            if (not isinstance(acceptable, list) or not acceptable
                    or any(type(status) is not int or not 400 <= status <= 499 or status == 429 for status in acceptable)
                    or len(set(acceptable)) != len(acceptable)):
                raise ValueError("acceptable_status must be a unique nonempty list of HTTP status integers")
        if differential:
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
            pagination = rule.get("pagination")
            if pagination is not None:
                _keys(pagination, {"param", "max_pages"}, {"param", "max_pages"})
                if (not isinstance(pagination["param"], str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", pagination["param"])
                        or type(pagination["max_pages"]) is not int or not 1 <= pagination["max_pages"] <= 100):
                    raise ValueError("pagination requires a parameter name and max_pages from 1 to 100")
            if "require_primary_canary" in rule and type(rule["require_primary_canary"]) is not bool:
                raise ValueError("require_primary_canary must be boolean")
            scope = rule.get("scope", "object")
            if scope not in {"object", "caller", "shared"}:
                raise ValueError("scope must be object, caller or shared")
            require_owner_canary = rule.get("require_owner_canary_in_baseline", False)
            if type(require_owner_canary) is not bool:
                raise ValueError("require_owner_canary_in_baseline must be boolean")
            if require_owner_canary and not canaries:
                raise ValueError("require_owner_canary_in_baseline requires leak_detection.canaries")
            if scope == "caller" and require_owner_canary is not True:
                raise ValueError("caller scope requires require_owner_canary_in_baseline: true")
            if scope == "caller" and not canaries:
                raise ValueError("caller scope requires leak_detection.canaries")
        if mutating and (set(auth) != {"primary", "forbidden"} or auth["primary"] == auth["forbidden"]):
            raise ValueError("Mutating rules require distinct primary and forbidden contexts")


def load_rules(paths: Iterable[str], *, accept_generated: bool = False) -> list[dict[str, Any]]:
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
    _validate_rules(rules, require_mutating=True, accept_generated=accept_generated)
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
    def __init__(self, inventory, client, contexts, variables, auth=None):
        self.inventory = inventory
        self.client = client
        self.contexts = contexts
        self.variables = variables
        self.auth = auth
        self.notes = set()
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
        if self.auth is not None:
            try:
                await self.auth.ensure(context)
            except AuthError as exc:
                raise _Stop(exc.message, "error", exc.reason) from None
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
            response = await self.client.request(endpoint["method"], inputs["url"], **kwargs)
            if (self.auth is not None and response.status_code == 401
                    and self.auth.can_refresh_on_401(context)):
                try:
                    await self.auth.refresh(context)
                except AuthError as exc:
                    raise _Stop(exc.message, "error", exc.reason) from None
                headers = dict(inputs["headers"])
                headers.update({key.lower(): value for key, value in self.headers(context).items()})
                headers.setdefault("cookie", "")
                kwargs["headers"] = headers
                response = await self.client.request(endpoint["method"], inputs["url"], **kwargs)
                self.notes.add("auth_refreshed")
            return response
        except UnsafeRequest:
            raise _Stop("Request blocked by the safety guard.", "skipped", "safety_blocked") from None
        except httpx.TimeoutException:
            if timeout_is_inconclusive:
                raise _Stop("HTTP request timed out.", "inconclusive", "timeout") from None
            raise _Stop("HTTP request timed out.", "error", "timeout") from None
        except Exception:
            raise _Stop("HTTP request failed.", "error", "execution_error") from None

    async def custom_request(self, spec, variables, primary=None, forbidden=None):
        """Execute a validated restore/verify request without trusting the spec."""
        role = spec.get("auth", "primary")
        if role == "none":
            context = None
        elif role == "primary":
            context = primary
        elif role == "forbidden":
            context = forbidden
        elif role in self.contexts:
            context = role
        else:
            raise _Stop("Unknown mutation request authentication context.", "error", "execution_error")

        def substitute(match):
            value = _lookup(variables, match[1])
            if value is _MISSING or value is None or isinstance(value, (dict, list)):
                raise _Stop("Unresolved mutation request path parameter.", "error", "execution_error")
            return quote(str(value), safe="")

        path = _TEMPLATE.sub(substitute, spec["path"])
        if "{{" in path or "}}" in path:
            raise _Stop("Malformed mutation request path parameter.", "error", "execution_error")
        headers = {key.lower(): value for key, value in self.headers(context).items()}
        headers.setdefault("cookie", "")
        query = _expand(spec.get("query", {}), variables)
        if not isinstance(query, dict):
            raise _Stop("Mutation request query is invalid.", "error", "execution_error")
        kwargs = {"params": query, "headers": headers, "follow_redirects": False, "auth": None}
        if "body" in spec:
            kwargs["json"] = _expand(spec["body"], variables)
        url = self.inventory["base_url"].rstrip("/") + path
        try:
            if self.auth is not None:
                await self.auth.ensure(context)
                headers.update({key.lower(): value for key, value in self.headers(context).items()})
                kwargs["headers"] = headers
            response = await self.client.request(spec["method"], url, **kwargs)
            if (self.auth is not None and response.status_code == 401
                    and self.auth.can_refresh_on_401(context)):
                await self.auth.refresh(context)
                headers.update({key.lower(): value for key, value in self.headers(context).items()})
                kwargs["headers"] = headers
                response = await self.client.request(spec["method"], url, **kwargs)
                self.notes.add("auth_refreshed")
            return response
        except UnsafeRequest:
            raise _Stop("Mutation request blocked by the safety guard.", "skipped", "safety_blocked") from None
        except httpx.TimeoutException:
            raise _Stop("Mutation request timed out.", "inconclusive", "timeout") from None
        except Exception:
            raise _Stop("Mutation request failed.", "error", "execution_error") from None

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


def _marker_present(response, marker: str) -> bool:
    try:
        payload = response.json()
    except (ValueError, TypeError):
        return marker in response.text

    def visit(value):
        if isinstance(value, dict):
            return any(visit(child) for child in value.values())
        if isinstance(value, list):
            return any(visit(child) for child in value)
        return isinstance(value, str) and marker in value

    return visit(payload)


def _state_hash(response, fields) -> str | None:
    try:
        payload = response.json()
        _json(payload)
    except (ValueError, TypeError, RecursionError):
        return None
    selected = []
    for field in fields:
        value = _lookup(payload, field)
        if value is _MISSING:
            return None
        selected.append([field, value])
    try:
        canonical = json.dumps(selected, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _mutation_host_allowed(url: str, allowed_hosts) -> bool:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        if ipaddress.ip_address(host).is_loopback:
            return True
    except ValueError:
        pass
    for entry in allowed_hosts:
        candidate = entry.strip().rstrip(".").lower()
        if candidate == host:
            return True
        try:
            if urlsplit("//" + candidate).hostname == host:
                return True
        except ValueError:
            continue
    return False


def _mutation_block_reason(allow_mutations: bool, allowed_hosts, read_only: bool,
                           base_url: str) -> str | None:
    missing = []
    if read_only:
        missing.append("--read-only is set")
    if not allow_mutations:
        missing.append("--allow-mutations is required")
    if not _mutation_host_allowed(base_url, allowed_hosts):
        host = (urlsplit(base_url).hostname or "unknown").lower()
        missing.append(f"--allow-host {host} is required")
    return "; ".join(missing) or None


async def _verify_mutation(runtime, verify, variables, marker, primary, forbidden,
                           before_hash=None):
    mode = verify["mode"]
    evidence = {"verification_mode": mode}
    if mode == "marker":
        evidence["marker_hash"] = hashlib.sha256(marker.encode("utf-8")).hexdigest()
        try:
            response = await runtime.custom_request(verify["readback"], variables, primary, forbidden)
        except _Stop:
            return {**evidence, "state": "unavailable"}
        if response.status_code == 429 or 500 <= response.status_code < 600 or not 200 <= response.status_code < 300:
            return {**evidence, "state": "unavailable"}
        return {**evidence, "state": "changed" if _marker_present(response, marker) else "unchanged"}

    if mode == "state_diff":
        try:
            response = await runtime.custom_request(verify["snapshot"], variables, primary, forbidden)
        except _Stop:
            return {**evidence, "state": "unavailable", "before_hash": before_hash}
        after_hash = _state_hash(response, verify["fields"])
        if (response.status_code == 429 or 500 <= response.status_code < 600
                or not 200 <= response.status_code < 300 or before_hash is None or after_hash is None):
            return {**evidence, "state": "unavailable", "before_hash": before_hash,
                    "after_hash": after_hash}
        return {**evidence, "state": "changed" if before_hash != after_hash else "unchanged",
                "before_hash": before_hash, "after_hash": after_hash}

    try:
        response = await runtime.custom_request(verify["request"], variables, primary, forbidden)
    except _Stop:
        return {**evidence, "state": "unavailable"}
    status = response.status_code
    evidence["probe_status"] = status
    if status == 429 or 500 <= status < 600:
        return {**evidence, "state": "unavailable", "probe_matched": False}
    matched = status == verify["expected_status"]
    if matched and "response_body" in verify:
        try:
            response.json()
        except (ValueError, TypeError):
            return {**evidence, "state": "unavailable", "probe_matched": False}
        assertion = {"type": "body", **verify["response_body"]}
        matched = all(item["passed"] for item in _assertions(response, [assertion], variables))
    evidence["probe_matched"] = bool(matched)
    return {**evidence, "state": "changed" if matched else "unchanged"}


async def _restore_mutation(runtime, rule, variables, primary, forbidden):
    for request in rule["restore"]:
        try:
            response = await runtime.custom_request(request, variables, primary, forbidden)
        except _Stop:
            raise _Stop(f"State restoration failed for rule '{rule['id']}'.",
                        "error", "restore_failed") from None
        if not 200 <= response.status_code < 300:
            raise _Stop(f"State restoration failed for rule '{rule['id']}'.",
                        "error", "restore_failed")


async def _execute_mutation(runtime, endpoint, inputs, forbidden, rule, variables, marker):
    verify = rule.get("verify")
    before_hash = None
    if verify and verify["mode"] == "state_diff":
        try:
            before = await runtime.custom_request(verify["snapshot"], variables,
                                                  rule["auth_contexts"]["primary"], forbidden)
            before_hash = _state_hash(before, verify["fields"])
        except _Stop:
            before_hash = None
        if before_hash is None:
            return {"status": "inconclusive", "verdict": "INCONCLUSIVE",
                    "message": "State snapshot was unavailable before the mutation.",
                    "reason": "verify_unavailable", "confidence": "reduced",
                    "evidence": {"verification_mode": "state_diff"}}

    attempted = False
    mutation = None
    verification = None
    error = None
    try:
        attempted = True
        try:
            response = await runtime.request(endpoint, inputs, forbidden, timeout_is_inconclusive=True)
        except _Stop as exc:
            if exc.reason == "timeout":
                mutation = {"error": "timeout"}
            else:
                error = exc
        if mutation is None and error is None:
            mutation = _response_record(response)
            if verify and 200 <= mutation.get("status", 0) < 300:
                verification = await _verify_mutation(
                    runtime, verify, variables, marker,
                    rule["auth_contexts"]["primary"], forbidden, before_hash,
                )
    except _Stop as exc:
        error = exc
    finally:
        restore_error = None
        if attempted:
            try:
                await _restore_mutation(runtime, rule, variables,
                                        rule["auth_contexts"]["primary"], forbidden)
            except _Stop as exc:
                restore_error = exc
        if restore_error is not None:
            raise restore_error
    if error is not None:
        raise error
    return evaluate_mutation(mutation=mutation, verification=verification,
                             acceptable_status=rule.get("acceptable_status", [401, 403, 404]))


def _race_config(race):
    idempotency = race.get("idempotency", {"mode": "none", "header": "Idempotency-Key"})
    return {
        "requests": race.get("requests", 10),
        "rounds": race.get("rounds", 5),
        "sync": race.get("sync", "last_byte"),
        "success_status": set(race.get("success_status", [200, 201, 204])),
        "idempotency": {"mode": idempotency.get("mode", "none"),
                        "header": idempotency.get("header", "Idempotency-Key")},
        "max_spread_ms": race.get("max_spread_ms", 5),
        "invariant": race["invariant"],
    }


def _race_identity(runtime, rule):
    name = rule["race"]["identity"]
    if name in {"primary", "forbidden"}:
        return rule["auth_contexts"][name]
    if name in runtime.contexts:
        return name
    raise _Stop("Race identity is not a configured context.", "error", "invalid_rule")


async def _race_reset(runtime, race, primary, forbidden):
    for request in race["reset"]:
        try:
            response = await runtime.custom_request(request, runtime.variables, primary, forbidden)
        except _Stop:
            return False
        if not 200 <= response.status_code < 300:
            return False
    return True


async def _race_snapshot(runtime, ledger, primary, forbidden):
    try:
        response = await runtime.custom_request(ledger["snapshot"], runtime.variables, primary, forbidden)
        payload = response.json()
        _json(payload)
    except (_Stop, ValueError, TypeError, RecursionError):
        return None
    if not 200 <= response.status_code < 300:
        return None
    value = _lookup(payload, ledger["path"])
    if (type(value) not in (int, float) or isinstance(value, bool)
            or not math.isfinite(value)):
        return None
    return value


async def _execute_race(runtime, endpoint, rule, variables, client, allowed_hosts):
    race = _race_config(rule["race"])
    auth = rule["auth_contexts"]
    primary, forbidden = auth["primary"], auth["forbidden"]
    identity = _race_identity(runtime, rule)
    op = endpoint.get("operation_id")
    rounds = []
    reset_failed = False
    sync_note = None
    sent = {}
    try:
        inputs = await runtime.inputs(endpoint, rule, identity, (op,) if op else (), [0])
        for _ in range(race["rounds"]):
            if not await _race_reset(runtime, rule["race"], primary, forbidden):
                reset_failed = True
                break
            ledger = race["invariant"].get("ledger")
            initial = None
            if ledger is not None:
                initial = await _race_snapshot(runtime, ledger, primary, forbidden)
                if initial is None:
                    rounds.append({"spread_ms": 0.0, "accepted": 0,
                                   "initial": None, "final": None,
                                   "status_counts": {}, "verify_unavailable": True})
                    break
            payloads = []
            same_key = secrets.token_urlsafe(24)
            idempotency = race["idempotency"]
            for _index in range(race["requests"]):
                headers = dict(inputs["headers"])
                if idempotency["mode"] != "none":
                    headers[idempotency["header"]] = (
                        same_key if idempotency["mode"] == "same"
                        else secrets.token_urlsafe(24))
                payload = {"method": endpoint["method"], "url": inputs["url"],
                           "headers": headers, "params": copy.deepcopy(inputs["query"])}
                if inputs["body"] is not _MISSING:
                    payload["json"] = copy.deepcopy(inputs["body"])
                payloads.append(payload)
            try:
                sent = await client.send_synchronized(
                    payloads, mode=race["sync"], max_spread_ms=race["max_spread_ms"],
                    inter_round_delay=0.05, allowed_hosts=allowed_hosts)
            except UnsafeRequest:
                raise _Stop("Race request blocked by the safety guard.", "skipped", "safety_blocked") from None
            except (OSError, httpx.HTTPError):
                raise _Stop("Synchronized race request failed.", "error", "execution_error") from None
            sync_note = sent.get("note") if sent.get("note") in {
                "h2_unavailable", "h2_coalesce_limit"} else sync_note
            counts = {}
            accepted = 0
            for record in sent.get("responses", []):
                if "error" in record:
                    key = "timeout" if record["error"] == "timeout" else "500"
                    counts[key] = counts.get(key, 0) + 1
                    continue
                status = record.get("status")
                if type(status) is not int:
                    counts["500"] = counts.get("500", 0) + 1
                    continue
                counts[str(status)] = counts.get(str(status), 0) + 1
                if status in race["success_status"]:
                    accepted += 1
            final = None
            verify_unavailable = False
            if ledger is not None:
                final = await _race_snapshot(runtime, ledger, primary, forbidden)
                verify_unavailable = final is None
            rounds.append({"spread_ms": sent.get("spread_ms", 0.0),
                           "accepted": accepted, "initial": initial, "final": final,
                           "status_counts": counts,
                           "verify_unavailable": verify_unavailable})
            if verify_unavailable:
                break
    finally:
        await _restore_mutation(runtime, rule, variables, primary, forbidden)
    return evaluate_race(rounds=rounds, requests=race["requests"],
                         max_spread_ms=race["max_spread_ms"],
                         min_rounds=5, sync_mode=sent.get("mode", race["sync"]),
                         invariant=race["invariant"], idempotency=race["idempotency"],
                         reset_failed=reset_failed, sync_note=sync_note)


def _differential_config(rule, variables):
    leak = rule["leak_detection"]
    canaries = _expand(leak.get("canaries", []), variables)
    if any(isinstance(value, (dict, list)) for value in canaries):
        raise _Stop("Canary values must resolve to scalar JSON values.", reason="invalid_canary")
    return {"acceptable_status": rule.get("acceptable_status", [401, 403, 404]),
            "canaries": canaries, "min_unique_leaf_values": leak.get("min_unique_leaf_values", 2),
            "ignore_fields": leak.get("ignore_fields", []),
            "scope": rule.get("scope", "object"),
            "require_owner_canary_in_baseline": rule.get("require_owner_canary_in_baseline", False)}


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


def _synthetic_endpoint(inventory, target):
    """Build the minimum endpoint record needed to execute a rule absent from the spec."""
    parameters = [{"name": name, "in": "path", "required": True, "schema": {"type": "string"}}
                  for name in _PATH_PARAMETER.findall(target["path"])]
    return {"path": target["path"], "method": target["method"], "parameters": parameters,
            "request_body": None, "operation_id": None, "base_url": inventory["base_url"]}


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


async def _scoped_differential_result(runtime, endpoint, inputs, forbidden, rule, baseline, comparison):
    """Run a caller/shared rule without object-control traffic."""
    async def observe(context):
        try:
            response = await runtime.request(endpoint, inputs, context, timeout_is_inconclusive=True)
            return _response_record(response)
        except _Stop as exc:
            if exc.reason == "timeout":
                return {"error": "timeout"}
            raise

    baseline_record = _response_record(baseline)
    forbidden_record = await observe(forbidden)
    evaluate = {"scope": comparison["scope"], "baseline": baseline_record,
                "forbidden": forbidden_record, "acceptable_status": comparison["acceptable_status"],
                "canaries": comparison["canaries"],
                "min_unique_leaf_values": comparison["min_unique_leaf_values"],
                "ignore_fields": comparison["ignore_fields"],
                "require_owner_canary_in_baseline": comparison["require_owner_canary_in_baseline"]}
    provisional = evaluate_scoped(confirm=0, **evaluate)
    confirmations = []
    if provisional["status"] == "failed":
        for _ in range(rule.get("confirm", 2)):
            observation = await observe(forbidden)
            confirmations.append(observation)
            if observation.get("error") or observation.get("status") == 429 or observation.get("status", 0) >= 500:
                break
    return evaluate_scoped(confirm=rule.get("confirm", 2), confirm_responses=confirmations, **evaluate)


async def _differential_result(runtime, endpoint, inputs, forbidden, rule, baseline, comparison):
    if comparison.get("scope", "object") != "object":
        return await _scoped_differential_result(runtime, endpoint, inputs, forbidden, rule, baseline, comparison)

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
    evaluate = {"baseline": baseline_record, "forbidden": forbidden_record,
                "acceptable_status": comparison["acceptable_status"],
                "canaries": comparison["canaries"],
                "min_unique_leaf_values": comparison["min_unique_leaf_values"],
                "ignore_fields": comparison["ignore_fields"]}
    # Overload and unsupported statuses need no extra traffic. Accepted denials
    # still run the unauthenticated control to detect public owner-data leaks.
    status = forbidden_record.get("status", 0)
    if not 200 <= status < 300 and status not in comparison["acceptable_status"]:
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
            observation = await observe(anonymous, None) if provisional.get("reason") == "unauthenticated_leak" else await observe(inputs, forbidden)
            confirmations.append(observation)
            # Stop on overload/timeouts; do not hammer an unhealthy target.
            if observation.get("error") or observation.get("status") == 429 or observation.get("status", 0) >= 500:
                break
    return evaluate_differential(confirm=rule.get("confirm", 2), confirm_responses=confirmations, **evaluate)


async def run_rules(inventory: dict, rules: list[dict], client,
                    contexts: dict | None = None, variables: dict | None = None,
                    spec_check: str = "strict", allow_mutations: bool = False,
                    allowed_hosts=(), read_only: bool = False,
                    accept_generated: bool = False, auth_manager=None) -> list[dict]:
    """Execute selected rules through an async guarded client; return redacted results.

    Invalid rules/context/variable configuration raises ValueError before any HTTP.
    Per-endpoint resolution, transport and baseline failures become result records.
    """
    _validate_rules(rules, require_mutating=False, accept_generated=accept_generated)
    if spec_check not in {"strict", "warn"}:
        raise ValueError("spec_check must be strict or warn")
    if not isinstance(allow_mutations, bool):
        raise ValueError("allow_mutations must be boolean")
    if isinstance(allowed_hosts, str):
        raise ValueError("allowed_hosts must be an iterable of host names")
    allowed_hosts = tuple(allowed_hosts)
    if any(not isinstance(host, str) or not host.strip() for host in allowed_hosts):
        raise ValueError("allowed_hosts must contain nonempty strings")
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
    runtime = _Runtime(inventory, client, contexts, variables, auth=auth_manager)
    results = []
    for rule in rules:
        for target in rule["target_endpoints"]:
            selected_type = check_type(rule)
            roles = identity_roles(rule)
            result = {key: rule[key] for key in ("name", "severity", "owasp_category", "cvss_score")}
            result.update(rule_id=rule["id"], severity=rule["severity"].lower(),
                          path=target["path"], method=target["method"],
                          path_template=target["path"], check_type=selected_type,
                          cwe=cwe_for(selected_type),
                          identity_roles=roles, cvss=resolve_cvss(rule, selected_type),
                          fingerprint=fingerprint(rule_id=rule["id"], method=target["method"],
                                                  path_template=target["path"],
                                                  identity_roles=roles,
                                                  check_type=selected_type))
            if "remediation" in rule:
                result["remediation"] = rule["remediation"]
            try:
                effective_spec_check = rule.get("spec_check", spec_check)
                if effective_spec_check not in {"strict", "warn"}:
                    raise ValueError("spec_check must be strict or warn")
                matches = [e for e in inventory["endpoints"]
                           if e["path"] == target["path"] and e["method"] == target["method"]]
                spec_drift = None
                if not matches:
                    if effective_spec_check == "strict":
                        raise _Stop("Selected endpoint is absent from inventory; rerun with --spec-check warn to execute it.",
                                    "skipped", "endpoint_absent")
                    endpoint = _synthetic_endpoint(inventory, target)
                    spec_drift = target["path"]
                else:
                    if len(matches) != 1:
                        raise _Stop("Selected endpoint is ambiguous in inventory.")
                    endpoint = matches[0]
                    if endpoint.get("traffic_only"):
                        spec_drift = "traffic inventory: " + target["path"]
                if spec_drift:
                    result["spec_drift"] = spec_drift
                if rule.get("disabled"):
                    result.update(status="skipped", verdict="SKIPPED",
                                  reason="rule_disabled",
                                  message="Generated rule is disabled; review it and add restore/verify before enabling.")
                    results.append(result)
                    continue
                differential = "leak_detection" in rule
                comparison = _differential_config(rule, variables) if differential else None
                auth = rule.get("auth_contexts", {})
                primary, forbidden = auth.get("primary"), auth.get("forbidden")
                if differential and (primary is None or forbidden is None):
                    raise _Stop("Differential rules require primary and forbidden contexts.", "error", "invalid_rule")
                runtime.headers(primary)
                runtime.headers(forbidden)
                op = endpoint.get("operation_id")
                mutating = rule.get("mutating", False)
                if mutating:
                    if primary is None or forbidden is None:
                        raise _Stop("Mutating rules require primary and forbidden contexts.",
                                    "error", "invalid_rule")
                    missing = _mutation_block_reason(allow_mutations, allowed_hosts, read_only,
                                                     inventory["base_url"])
                    if missing:
                        raise _Stop(f"Mutation blocked: {missing}.", "skipped", "mutation_blocked")
                    if "race" in rule:
                        result.update(await _execute_race(runtime, endpoint, rule,
                                                          runtime.variables, client, allowed_hosts))
                        results.append(result)
                        continue
                    marker = secrets.token_urlsafe(24)
                    original_variables = runtime.variables
                    runtime.variables = {**original_variables, "marker": marker}
                    try:
                        inputs = await runtime.inputs(endpoint, rule, primary, (op,) if op else (), [0])
                        result.update(await _execute_mutation(runtime, endpoint, inputs, forbidden,
                                                              rule, runtime.variables, marker))
                    finally:
                        runtime.variables = original_variables
                    results.append(result)
                    continue
                inputs = await runtime.inputs(endpoint, rule, primary, (op,) if op else (), [0])
                pagination = rule.get("pagination")
                if pagination:
                    inputs["query"][pagination["param"]] = 1
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
                    if baseline.status_code == 401 and runtime.auth is not None:
                        raise _Stop("Primary baseline returned 401; check the auth configuration.",
                                    "error", "baseline_unauthorized")
                    if not 200 <= baseline.status_code < 300:
                        raise _Stop("Primary baseline did not return 2xx; forbidden request not sent.",
                                    "error", "baseline_not_2xx")
                    runtime.remember(endpoint, baseline, primary)
                if differential:
                    if rule.get("require_primary_canary") or comparison.get("require_owner_canary_in_baseline"):
                        try:
                            baseline_values = _values(_response_record(baseline), set(comparison["ignore_fields"]))
                        except Exception:
                            baseline_values = set()
                        if not any(_typed(value) in baseline_values for value in comparison["canaries"]):
                            raise _Stop("Primary baseline did not contain a required canary.", "error", "baseline_missing_canary")
                    page_results = [await _differential_result(runtime, endpoint, inputs, forbidden,
                                                               rule, baseline, comparison)]
                    owner_pages = [bool({_typed(value) for value in comparison["canaries"]}
                                        & _values(_response_record(baseline), set(comparison["ignore_fields"])))]
                    if pagination:
                        for page in range(2, pagination["max_pages"] + 1):
                            page_inputs = {**inputs, "query": {**inputs["query"], pagination["param"]: page}}
                            # Keep the shared missing-body sentinel by identity; deepcopy would turn it into JSON data.
                            page_baseline = await runtime.request(endpoint, page_inputs, primary)
                            if not 200 <= page_baseline.status_code < 300:
                                page_results.append({"status": "error", "verdict": "ERROR", "reason": "baseline_not_2xx",
                                                     "message": "Primary paginated baseline did not return 2xx."})
                                break
                            owner_pages.append(bool({_typed(value) for value in comparison["canaries"]}
                                                    & _values(_response_record(page_baseline), set(comparison["ignore_fields"]))))
                            page_results.append(await _differential_result(runtime, endpoint, page_inputs, forbidden,
                                                                           rule, page_baseline, comparison))
                    selected_result = next((item for item in page_results if item["status"] == "failed"), None)
                    selected_result = selected_result or next((item for item in page_results if item["status"] == "error"), None)
                    # Public-only pages cannot clear an unwalked scan. Once an owner-positive
                    # page is tested, only its ambiguities (or other unhealthy pages) block PASS.
                    owner_tested = any(owner_pages)
                    selected_result = selected_result or next((item for index, item in enumerate(page_results)
                        if item["status"] == "inconclusive" and not (
                            pagination and owner_tested and not owner_pages[index]
                            and item.get("reason") == "ambiguous_2xx")), None)
                    selected_result = selected_result or next((item for item in page_results if item["status"] == "passed"), page_results[0])
                    if pagination:
                        selected_result = {**selected_result, "evidence": {**selected_result.get("evidence", {}),
                                                                              "pages_walked": len(page_results)}}
                    result.update(selected_result)
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
    if runtime.notes:
        for result in results:
            result.setdefault("note", "auth_refreshed")
    return results
