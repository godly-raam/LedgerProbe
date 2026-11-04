"""Offline HAR/Postman import, traffic templating, and spec drift.

The importer never opens a network socket. Raw values are parsed only in memory
to detect path variation and owner-only JSON leaves; artifacts retain schema
names, templates, and allowlisted canaries/object IDs only.
"""
from __future__ import annotations

import base64
import json
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlsplit

import yaml

from .parser import build_graph

_STATIC = {
    "api", "v1", "v2", "v3", "objects", "object", "items", "item", "accounts",
    "account", "users", "user", "profile", "shared", "paginated", "mutate",
    "login", "orders", "order", "products", "product", "health", "status",
    "search", "graphql", "auth", "oauth", "token", "me", "self", "public",
    "keys", "blobs", "solo", "catalog", "files", "reports", "events", "sessions",
}
_VERSION = re.compile(r"v\d+(?:\.\d+)?\Z", re.I)
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z", re.I)
_OBJECT_ID = re.compile(r"[0-9a-f]{24}\Z", re.I)
_LONG_HEX = re.compile(r"[0-9a-f]{16,}\Z", re.I)
_BASE64URL = re.compile(r"[A-Za-z0-9_-]{16,}\Z")
_INTEGER = re.compile(r"[0-9]+\Z")
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\Z")
_EMAIL = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+", re.I)
_CARD = re.compile(r"\b(?:\d[ -]?){15,18}\d\b")
_PHONE = re.compile(r"\+?\d[\d ()\-]{8,}\d")
_TOKENISH = re.compile(r"(?i)(?:token|secret|bearer|api[_-]?key|session|password|cookie)")
_STATIC_EXT = re.compile(r"\.(?:css|js|mjs|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|webp|avif|mp4|pdf)\Z", re.I)
_ANALYTICS = ("google-analytics", "googletagmanager", "doubleclick", "segment.io",
              "facebook.net", "hotjar", "mixpanel", "amplitude", "sentry.io")
_API_CONTENT = ("application/json", "application/problem+json", "application/graphql",
                "application/xml", "text/xml", "application/x-www-form-urlencoded",
                "multipart/form-data", "text/plain")


@dataclass
class Observation:
    role: str
    method: str
    host: str
    path: str
    query_names: tuple[str, ...]
    request_content_type: str
    response_content_type: str
    status: int
    request_schema: dict | None
    response_schema: dict | None
    response_json: Any = None
    graphql_operations: tuple[dict, ...] = ()
    warnings: tuple[str, ...] = ()
    template: str = ""
    confidence: str = "low"
    path_values: dict[str, str] = field(default_factory=dict)


@dataclass
class ImportResult:
    inventory: dict
    rules: list[dict]
    inputs: dict
    drift: dict | None
    warnings: list[str] = field(default_factory=list)


def _json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return None
    return value


def _schema(value: Any) -> dict:
    if value is None:
        return {"type": "null"}
    if type(value) is bool:
        return {"type": "boolean"}
    if type(value) is int:
        return {"type": "integer"}
    if type(value) is float:
        return {"type": "number"}
    if isinstance(value, list):
        return {"type": "array", "items": _schema(value[0]) if value else {}}
    if isinstance(value, dict):
        return {"type": "object", "properties": {key: _schema(child) for key, child in value.items()}}
    return {"type": "string"}


def _merge_schema(left: dict | None, right: dict | None) -> dict | None:
    if not left:
        return right
    if not right:
        return left
    if left.get("type") == "object" and right.get("type") == "object":
        properties = dict(left.get("properties", {}))
        for key, schema in right.get("properties", {}).items():
            properties[key] = _merge_schema(properties.get(key), schema)
        return {"type": "object", "properties": properties}
    if left.get("type") == "array" and right.get("type") == "array":
        return {"type": "array", "items": _merge_schema(left.get("items"), right.get("items"))}
    return left


def _fields(schema: dict | None, prefix: str = "") -> list[str]:
    if not isinstance(schema, dict):
        return []
    result = []
    for name, child in schema.get("properties", {}).items():
        path = f"{prefix}.{name}" if prefix else name
        result.append(path)
        result.extend(_fields(child, path))
    if isinstance(schema.get("items"), dict):
        result.extend(_fields(schema["items"], prefix + "[]"))
    return list(dict.fromkeys(result))


def _content_type(headers: Iterable[dict]) -> str:
    for header in headers:
        if str(header.get("name", "")).lower() == "content-type":
            return str(header.get("value", "")).split(";", 1)[0].strip().lower()
    return ""


def _api_content(value: str) -> bool:
    if not value:
        return True
    return any(value == item or value.endswith("+json") for item in _API_CONTENT)


def _sensitive(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return True
    return any(pattern.search(value) for pattern in (_JWT, _EMAIL, _CARD, _PHONE, _TOKENISH))


def _hosts(values: Iterable[str]) -> set[str]:
    return {str(value).strip().lower().rstrip(".") for value in values if str(value).strip()}


def _normal_path(path: str) -> str:
    if not path:
        return "/"
    path = "/" + path.lstrip("/")
    if len(path) > 1:
        path = path.rstrip("/")
    return path


def _keep(host: str, path: str, request_type: str, response_type: str,
          allowed: set[str], method: str) -> bool:
    if method == "OPTIONS" or host not in allowed:
        return False
    if any(item in host for item in _ANALYTICS):
        return False
    if _STATIC_EXT.search(path):
        return False
    if not _api_content(request_type) or not _api_content(response_type):
        return False
    return True


def _graphql(value: Any) -> tuple[dict, ...]:
    if not isinstance(value, dict):
        return ()
    query = value.get("query")
    if not isinstance(query, str):
        return ()
    match = re.match(r"\s*(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)", query)
    if not match and value.get("operationName"):
        return (({"name": str(value["operationName"]), "type": "query"},))
    if not match:
        return ()
    return (({"name": match.group(2), "type": match.group(1)},))


def _har_body(content: dict | None) -> Any:
    if not isinstance(content, dict):
        return None
    text = content.get("text")
    if isinstance(text, str) and content.get("encoding") == "base64":
        try:
            text = base64.b64decode(text).decode("utf-8", "replace")
        except (ValueError, TypeError):
            return None
    return _json(text)


def _observation(role: str, request: dict, response: dict, allowed: set[str]) -> Observation | None:
    url = request.get("url")
    if not isinstance(url, str):
        return None
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    method = str(request.get("method", "GET")).upper()
    path = _normal_path(parsed.path)
    request_type = _content_type(request.get("headers", []))
    response_type = _content_type(response.get("headers", []))
    if not _keep(host, path, request_type, response_type, allowed, method):
        return None
    query_names = tuple(sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}))
    request_json = _har_body(request.get("postData"))
    response_json = _har_body(response.get("content"))
    graphql = _graphql(request_json) if method == "POST" else ()
    return Observation(
        role=role, method=method, host=host, path=path, query_names=query_names,
        request_content_type=request_type, response_content_type=response_type,
        status=int(response.get("status", 0) or 0),
        request_schema=_schema(request_json) if request_json is not None else None,
        response_schema=_schema(response_json) if response_json is not None else None,
        response_json=response_json, graphql_operations=graphql,
    )


def _strong(value: str) -> bool:
    return any(pattern.fullmatch(value) for pattern in (_UUID, _OBJECT_ID, _LONG_HEX, _BASE64URL, _INTEGER))


def _literal(value: str) -> bool:
    return value.lower() in _STATIC or bool(_VERSION.fullmatch(value))


def _templates(observations: list[Observation]) -> list[Observation]:
    groups: dict[tuple[str, tuple[str, ...]], list[Observation]] = defaultdict(list)
    for observation in observations:
        skeleton = tuple(part if _literal(part) else "*"
                         for part in observation.path.strip("/").split("/"))
        groups[(observation.method, skeleton)].append(observation)
    for (method, _), group in groups.items():
        split = [item.path.strip("/").split("/") for item in group]
        dynamic: dict[int, str] = {}
        notes = set()
        for index in range(len(split[0])):
            values = [parts[index] for parts in split if index < len(parts)]
            unique = set(values)
            if len(unique) == 1 and _strong(values[0]):
                dynamic[index] = "id" if not dynamic else f"id{len(dynamic) + 1}"
            elif len(unique) >= 2 and not all(_literal(value) for value in unique):
                dynamic[index] = "id" if not dynamic else f"id{len(dynamic) + 1}"
        for observation, parts in zip(group, split):
            pieces = []
            values = {}
            for index, part in enumerate(parts):
                if index in dynamic:
                    name = dynamic[index]
                    pieces.append("{" + name + "}")
                    values[name] = part
                else:
                    pieces.append(part)
            observation.template = "/" + "/".join(pieces)
            observation.path_values = values
            strong = [index for index in dynamic if _strong(parts[index])]
            varied = [index for index in dynamic if not _strong(parts[index])]
            observation.confidence = "high" if strong else ("medium" if varied else ("high" if len(group) > 1 else "low"))
            if not dynamic and len(group) == 1:
                notes.add("single_observation_literal")
            observation.warnings = tuple(sorted(notes))
    return observations


def _values(value: Any, output: set[str]) -> None:
    if isinstance(value, dict):
        for child in value.values():
            _values(child, output)
    elif isinstance(value, list):
        for child in value:
            _values(child, output)
    elif isinstance(value, str) and not _sensitive(value):
        output.add(value)


def _endpoint_id(method: str, template: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", template.lower()).strip("_") or "root"
    return f"traffic_{method.lower()}_{slug[:80]}"


def _finalize(observations: list[Observation]) -> tuple[dict, dict]:
    observations = _templates(observations)
    endpoints: dict[tuple[str, str], dict] = {}
    for observation in observations:
        key = (observation.method, observation.template)
        endpoint = endpoints.get(key)
        if endpoint is None:
            endpoint = {
                "path": observation.template, "method": observation.method,
                "operation_id": _endpoint_id(observation.method, observation.template),
                "parameters": [], "request_body": None, "response_fields": [],
                "roles": [], "request_content_types": [], "response_content_types": [],
                "statuses": [], "graphql_operations": [], "warnings": [],
                "template_confidence": observation.confidence, "traffic_only": True,
                "source": "traffic",
            }
            endpoints[key] = endpoint
        endpoint["roles"] = sorted(set(endpoint["roles"]) | {observation.role})
        endpoint["statuses"] = sorted(set(endpoint["statuses"]) | {observation.status})
        endpoint["request_content_types"] = sorted(set(endpoint["request_content_types"]) |
                                                    ({observation.request_content_type} if observation.request_content_type else set()))
        endpoint["response_content_types"] = sorted(set(endpoint["response_content_types"]) |
                                                     ({observation.response_content_type} if observation.response_content_type else set()))
        endpoint["warnings"] = sorted(set(endpoint["warnings"]) | set(observation.warnings))
        endpoint["template_confidence"] = max((endpoint["template_confidence"], observation.confidence),
                                              key={"high": 3, "medium": 2, "low": 1}.get)
        endpoint["graphql_operations"] = list({item["name"] + ":" + item["type"]: item
                                                for item in endpoint["graphql_operations"] + list(observation.graphql_operations)}.values())
        endpoint["response_schema"] = _merge_schema(endpoint.get("response_schema"), observation.response_schema)
        endpoint["request_schema"] = _merge_schema(endpoint.get("request_schema"), observation.request_schema)
        endpoint["observations"] = endpoint.get("observations", []) + [observation]
    for endpoint in endpoints.values():
        observations = endpoint.pop("observations")
        split = endpoint["path"].strip("/").split("/")
        path_parameters = [part.strip("{}") for part in split if part.startswith("{") and part.endswith("}")]
        query_names = sorted({name for item in observations for name in item.query_names})
        endpoint["parameters"] = [
            {"name": name, "in": "path", "required": True, "schema": {"type": "string"}}
            for name in path_parameters
        ] + [
            {"name": name, "in": "query", "required": False, "schema": {"type": "string"}}
            for name in query_names
        ]
        endpoint["response_fields"] = _fields(endpoint.pop("response_schema", None))
        schema = endpoint.pop("request_schema", None)
        if schema is not None:
            media = next(iter(endpoint["request_content_types"]), "application/json") or "application/json"
            endpoint["request_body"] = {"required": False, "content": {media: {"schema": schema}}}
        endpoint.pop("observations", None)
    graphql_operations = []
    for endpoint in endpoints.values():
        for operation in endpoint.get("graphql_operations", []):
            graphql_operations.append({**operation, "method": endpoint["method"], "path": endpoint["path"]})
    graphql_operations = list({(item.get("type"), item.get("name"), item.get("path")): item
                                for item in graphql_operations}.values())
    inventory = {"base_url": "", "endpoints": sorted(endpoints.values(), key=lambda item: (item["path"], item["method"])),
                 "graph": build_graph(list(endpoints.values())), "source": "traffic",
                 "graphql_operations": graphql_operations}
    return inventory, _inputs(endpoints.values(), observations)


def _inputs(endpoints: Iterable[dict], observations: list[Observation]) -> dict:
    roles = sorted({item.role for item in observations})
    contexts = {}
    for role in roles:
        headers = {"Authorization": "Bearer REPLACE_ME"}
        if role in {"owner", "other"}:
            headers["X-Actor"] = role
        contexts[role] = headers
    variables = {"canaries": {}, "id_by_path": {}, "canary_by_path": {}}
    for endpoint in endpoints:
        path_names = [p["name"] for p in endpoint["parameters"] if p["in"] == "path"]
        path_variables = {}
        for name in path_names:
            value = next((obs.path_values.get(name) for obs in observations
                          if obs.template == endpoint["path"] and obs.role == "owner" and obs.path_values.get(name)), None)
            if value:
                variable = name
                suffix = 2
                while variable in variables and variables[variable] != value:
                    variable = f"{name}_{suffix}"
                    suffix += 1
                variables[variable] = value
                path_variables[name] = variable
        if path_variables:
            variables["id_by_path"][endpoint["path"]] = path_variables
        if endpoint["roles"] == ["other", "owner"] or set(endpoint["roles"]) == {"owner", "other"}:
            owner, other = set(), set()
            for obs in observations:
                if obs.template != endpoint["path"]:
                    continue
                _values(obs.response_json, owner if obs.role == "owner" else other)
            candidates = sorted(owner - other, key=lambda value: (-len(value), value))[:5]
            if candidates:
                variables["canaries"][endpoint["path"]] = candidates
                variable = "canary_value" if "canary_value" not in variables else f"canary_value_{len(variables['canaries']) + 1}"
                variables[variable] = candidates[0]
                variables["canary_by_path"][endpoint["path"]] = variable
    for key in ("canaries", "id_by_path", "canary_by_path"):
        if not variables[key]:
            variables.pop(key)
    return {"contexts": contexts, "variables": variables}


def _rule_slug(endpoint: dict) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", endpoint["path"].strip("/").lower()).strip("-") or "root"
    return endpoint["method"].lower() + "-" + slug


def _generated_rules(inventory: dict, inputs: dict, generated_from: str) -> list[dict]:
    rules = []
    roles = set(inputs.get("contexts", {}))
    variables = inputs.get("variables", {})
    for endpoint in inventory["endpoints"]:
        if endpoint.get("graphql_operations"):
            continue
        path_names = [p["name"] for p in endpoint["parameters"] if p["in"] == "path"]
        base = {
            "id": "generated-" + _rule_slug(endpoint),
            "name": "[Generated] Authorization check for " + endpoint["method"] + " " + endpoint["path"],
            "severity": "high", "owasp_category": "API1:2023", "cvss_score": 8.1,
            "target_endpoints": [{"path": endpoint["path"], "method": endpoint["method"]}],
            "generated_from": generated_from, "review_required": True,
        }
        if endpoint["method"] != "GET":
            rules.append({**base, "disabled": True, "mutating": True,
                          "auth_contexts": {"primary": "owner", "forbidden": "other"}})
            continue
        if not {"owner", "other"} <= roles:
            continue
        canary_variable = variables.get("canary_by_path", {}).get(endpoint["path"])
        canaries = ["{{" + canary_variable + "}}"] if canary_variable else []
        leak = {"min_unique_leaf_values": 2, "ignore_fields": []}
        if canaries:
            leak["canaries"] = canaries
        if path_names:
            path_variables = variables.get("id_by_path", {}).get(endpoint["path"], {})
            rule = {**base, "scope": "object", "scope_confidence": endpoint["template_confidence"],
                    "auth_contexts": {"primary": "owner", "forbidden": "other"},
                    "parameters": {"path": {name: "{{" + path_variables.get(name, name) + "}}"
                                             for name in path_names}},
                    "acceptable_status": [401, 403, 404], "leak_detection": leak,
                    "controls": {"nonexistent_object": True, "unauthenticated": True}, "confirm": 2}
            rules.append(rule)
        else:
            rule = {**base, "scope": "caller", "scope_confidence": "low",
                    "auth_contexts": {"primary": "owner", "forbidden": "other"},
                    "acceptable_status": [401, 403, 404], "leak_detection": leak,
                    "require_owner_canary_in_baseline": True, "confirm": 2}
            if not canaries:
                rule["disabled"] = True
            rules.append(rule)
    return rules


def _spec_inventory(spec: Path) -> dict:
    from .parser import parse_document
    document = yaml.safe_load(spec.read_text(encoding="utf-8"))
    return parse_document(document, str(spec))


def load_spec_inventory(spec: Path) -> dict:
    return _spec_inventory(Path(spec))


def drift_report(spec_inventory: dict, traffic_inventory: dict) -> dict:
    def rows(inventory):
        return {(endpoint["method"], endpoint["path"]): endpoint
                for endpoint in inventory.get("endpoints", [])}
    spec, traffic = rows(spec_inventory), rows(traffic_inventory)
    undocumented = [{"method": method, "path": path} for method, path in sorted(set(traffic) - set(spec))]
    unobserved = [{"method": method, "path": path} for method, path in sorted(set(spec) - set(traffic))]
    parameter_mismatches = []
    method_mismatches = []
    for key in sorted(set(spec) & set(traffic)):
        spec_params = sorted(p["name"] for p in spec[key].get("parameters", []))
        traffic_params = sorted(p["name"] for p in traffic[key].get("parameters", []))
        if spec_params != traffic_params:
            parameter_mismatches.append({"method": key[0], "path": key[1],
                                         "spec": spec_params, "traffic": traffic_params})
    for (spec_method, path) in spec:
        traffic_methods = {method for method, item_path in traffic if item_path == path}
        if traffic_methods and spec_method not in traffic_methods:
            method_mismatches.append({"path": path, "spec": [spec_method], "traffic": sorted(traffic_methods)})
    return {"counts": {"undocumented": len(undocumented), "unobserved": len(unobserved),
                        "parameter_mismatches": len(parameter_mismatches),
                        "method_mismatches": len(method_mismatches)},
            "undocumented": undocumented, "unobserved": unobserved,
            "parameter_mismatches": parameter_mismatches, "method_mismatches": method_mismatches}


def import_har(roles: dict[str, Path], include_hosts: Iterable[str], source: str = "har",
               spec: Path | None = None) -> ImportResult:
    allowed = _hosts(include_hosts)
    observations = []
    for role, path in roles.items():
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        entries = document.get("log", {}).get("entries")
        if document.get("log", {}).get("version") != "1.2" or not isinstance(entries, list):
            raise ValueError("HAR must be version 1.2 with a log.entries list")
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
                continue
            observed = _observation(role, entry["request"], entry.get("response", {}), allowed)
            if observed:
                observations.append(observed)
    inventory, inputs = _finalize(observations)
    rules = _generated_rules(inventory, inputs, "har")
    drift = drift_report(_spec_inventory(spec), inventory) if spec else None
    return ImportResult(inventory, rules, inputs, drift,
                        [item for endpoint in inventory["endpoints"] for item in endpoint["warnings"]])


def _postman_request(role: str, item: dict, allowed: set[str]) -> Observation | None:
    request = item.get("request")
    if not isinstance(request, dict):
        return None
    url = request.get("url")
    raw = url if isinstance(url, str) else (url or {}).get("raw")
    if not isinstance(raw, str):
        if isinstance(url, dict):
            host = ".".join(url.get("host", [])) if isinstance(url.get("host"), list) else url.get("host", "")
            path = "/".join(url.get("path", [])) if isinstance(url.get("path"), list) else url.get("path", "")
            raw = f"{url.get('protocol', 'https')}://{host}/{path}"
        else:
            return None
    parsed = urlsplit(raw)
    headers = request.get("header", [])
    request_type = _content_type(headers)
    body = request.get("body") or {}
    request_json = _json(body.get("raw")) if body.get("mode") == "raw" else None
    response_json = None
    response_type = ""
    status = 0
    responses = item.get("response", [])
    if isinstance(responses, list) and responses:
        first = responses[0] if isinstance(responses[0], dict) else {}
        response_json = _json(first.get("body"))
        status = int(first.get("code", 0) or 0)
        response_type = _content_type(first.get("header", []))
    observation = Observation(
        role=role, method=str(request.get("method", "GET")).upper(),
        host=(parsed.hostname or "").lower(), path=_normal_path(parsed.path),
        query_names=tuple(sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)})),
        request_content_type=request_type, response_content_type=response_type,
        status=status, request_schema=_schema(request_json) if request_json is not None else None,
        response_schema=_schema(response_json) if response_json is not None else None,
        response_json=response_json,
        graphql_operations=_graphql(request_json) if str(request.get("method", "GET")).upper() == "POST" else (),
    )
    return observation if _keep(observation.host, observation.path, request_type, response_type, allowed,
                                observation.method) else None


def import_postman(roles: dict[str, Path], include_hosts: Iterable[str], source: str = "postman",
                   spec: Path | None = None) -> ImportResult:
    allowed = _hosts(include_hosts)
    observations = []
    for role, path in roles.items():
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(document.get("info"), dict) or "2.1.0" not in str(document["info"].get("schema", "")):
            raise ValueError("Postman collection must be v2.1.0")
        def walk(items):
            for item in items if isinstance(items, list) else []:
                if not isinstance(item, dict):
                    continue
                if "item" in item:
                    walk(item["item"])
                else:
                    observed = _postman_request(role, item, allowed)
                    if observed:
                        observations.append(observed)
        walk(document.get("item"))
    inventory, inputs = _finalize(observations)
    return ImportResult(inventory, _generated_rules(inventory, inputs, "postman"), inputs,
                        drift_report(_spec_inventory(spec), inventory) if spec else None)


def import_mitm(roles: dict[str, Path], include_hosts: Iterable[str], source: str = "mitm",
                spec: Path | None = None) -> ImportResult:
    try:
        from mitmproxy.io import FlowReader  # type: ignore
    except ImportError:
        raise ImportError("mitmproxy flow import requires the optional 'ledgerprobe[mitm]' extra") from None
    allowed = _hosts(include_hosts)
    observations = []
    for role, path in roles.items():
        with Path(path).open("rb") as stream:
            for flow in FlowReader(stream).stream():
                request, response = flow.request, flow.response
                if request is None or response is None:
                    continue
                request_json = _json(request.text)
                response_json = _json(response.text)
                observed = Observation(
                    role=role, method=request.method.upper(), host=request.host.lower(),
                    path=_normal_path(request.path), query_names=tuple(sorted({k for k, _ in request.query.items()})),
                    request_content_type=request.headers.get("content-type", "").split(";", 1)[0].lower(),
                    response_content_type=response.headers.get("content-type", "").split(";", 1)[0].lower(),
                    status=response.status_code, request_schema=_schema(request_json) if request_json is not None else None,
                    response_schema=_schema(response_json) if response_json is not None else None,
                    response_json=response_json, graphql_operations=_graphql(request_json) if request.method == "POST" else (),
                )
                if _keep(observed.host, observed.path, observed.request_content_type,
                         observed.response_content_type, allowed, observed.method):
                    observations.append(observed)
    inventory, inputs = _finalize(observations)
    return ImportResult(inventory, _generated_rules(inventory, inputs, "mitm"), inputs,
                        drift_report(_spec_inventory(spec), inventory) if spec else None)


def _git_ignored(path: Path) -> bool:
    try:
        result = subprocess.run(["git", "check-ignore", "-q", str(path.resolve())],
                                capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def write_import(result: ImportResult, out: Path, *, allow_tracked_output: bool = False) -> list[Path]:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    inputs_path = out / "inputs.generated.json"
    if not allow_tracked_output and not _git_ignored(inputs_path):
        raise ValueError("inputs.generated.json is not git-ignored; pass --allow-tracked-output explicitly")
    inventory_path, drift_path, rules_path = out / "inventory.json", out / "drift.json", out / "rules.generated.yaml"
    inventory_path.write_text(json.dumps(result.inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    rules_text = yaml.safe_dump(result.rules, sort_keys=False)
    if any(rule.get("disabled") for rule in result.rules):
        rules_text = "# REVIEW: add restore: and verify: before enabling mutation rules\n" + rules_text
    rules_path.write_text(rules_text, encoding="utf-8")
    inputs_path.write_text(json.dumps(result.inputs, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    inputs_path.chmod(0o600)
    paths = [inventory_path, rules_path, inputs_path]
    drift = result.drift or {
        "counts": {"undocumented": 0, "unobserved": 0,
                   "parameter_mismatches": 0, "method_mismatches": 0},
        "undocumented": [], "unobserved": [],
        "parameter_mismatches": [], "method_mismatches": [],
    }
    drift_path.write_text(json.dumps(drift, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths.insert(1, drift_path)
    return paths


def load_traffic_inventory(path: Path) -> dict:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("endpoints"), list):
        raise ValueError("traffic inventory must contain an endpoints list")
    for endpoint in document["endpoints"]:
        if (not isinstance(endpoint, dict) or not isinstance(endpoint.get("path"), str)
                or not endpoint.get("path", "").startswith("/")
                or not isinstance(endpoint.get("method"), str)):
            raise ValueError("traffic inventory contains an invalid endpoint")
    return document


def merge_traffic_inventory(inventory: dict, traffic: dict) -> dict:
    existing = {(endpoint["method"], endpoint["path"]) for endpoint in inventory["endpoints"]}
    for endpoint in traffic.get("endpoints", []):
        if (endpoint["method"], endpoint["path"]) not in existing:
            inventory["endpoints"].append({
                "operation_id": endpoint.get("operation_id") or _endpoint_id(endpoint["method"], endpoint["path"]),
                **endpoint, "traffic_only": True,
            })
    inventory["graph"] = build_graph(inventory["endpoints"])
    return inventory