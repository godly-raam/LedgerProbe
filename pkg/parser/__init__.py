"""Target-agnostic OpenAPI 2/3/3.1 and Postman 2.1 inventory parsing.

``request_body`` is None or ``{'required': bool, 'content': {media_type:
{'schema': dict | bool, 'example': any (optional), 'examples': dict (optional)}}}``.
OpenAPI 2 body/form parameters and Postman bodies use this same shape. Parameter
examples live beside their schema; concrete values are never replaced by guesses.
``response_fields`` contains dotted property paths (``[]`` marks array items).

Graph entries are ``{'source': operation_id, 'target': operation_id,
'field': response_field, 'parameter': parameter_name}``. Exact field paths or
bare leaf names are matched to path/query inputs and top-level required JSON body
properties. Array-item fields are not inferred; ambiguous candidates are retained. These are candidate data-flow
hints, not permission or instructions to substitute values; runtime decisions
belong to the rules module. No ID aliases, singularization, or URL guesses occur.
Local JSON pointers and unique schema anchors are expanded; cycles retain an
unresolved $ref and excessive resolution depth raises ValueError. External refs are rejected even in unused components,
before validator execution. Postman enabled inputs are required; unknown variables
stay literal. Postman auth metadata can contain credentials: treat it as sensitive.
"""

import copy
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urljoin, urlsplit

import yaml

__all__ = ["build_graph", "load_inventory", "parse_document"]

_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
_MAX_DEPTH = 40
_VARIABLE = re.compile(r"\{\{([^{}]+)\}\}")


async def load_inventory(source: str, client) -> dict:
    """Load JSON/YAML from a local path or through the supplied guarded client.

    HTTP(S) responses must expose ``text`` and may expose ``raise_for_status``.
    No client is created here, and no reference triggers any network request.
    """
    if not isinstance(source, str) or not source.strip():
        raise ValueError("source must be a non-empty path or HTTP(S) URL")
    scheme = urlsplit(source).scheme.lower()
    if scheme in {"http", "https"}:
        if client is None:
            raise ValueError("URL sources require a guarded client")
        response = await client.get(source)
        if hasattr(response, "raise_for_status"):
            response.raise_for_status()
        text = response.text
    elif scheme:
        raise ValueError(f"Unsupported source scheme: {scheme}; use HTTP(S) or a local path")
    else:
        text = Path(source).read_text(encoding="utf-8")
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid JSON/YAML document: {exc}") from exc
    return parse_document(document, source)


def _check_refs(value, active=None, depth=0, check_references=True):
    if not isinstance(value, (dict, list)):
        return
    active = set() if active is None else active
    if id(value) in active or depth > 100:
        raise ValueError("Document contains a YAML alias cycle or excessive nesting")
    active.add(id(value))
    try:
        if isinstance(value, dict):
            for keyword in ("$ref", "$dynamicRef", "$recursiveRef") if check_references else ():
                if keyword not in value:
                    continue
                ref = value[keyword]
                if not isinstance(ref, str):
                    raise ValueError(f"{keyword} must be a string")
                if not ref.startswith("#"):
                    raise ValueError(
                        f"External {keyword} {ref!r} is unsupported; "
                        "bundle references into local #/ pointers before parsing"
                    )
            children = value.values()
        else:
            children = value
        for child in children:
            _check_refs(child, active, depth + 1, check_references)
    finally:
        active.remove(id(value))


def _pointer(document, ref):
    fragment = unquote(ref[1:])
    if fragment and not fragment.startswith("/"):
        matches = []

        def find_anchor(value):
            if isinstance(value, dict):
                if value.get("$anchor") == fragment or value.get("$dynamicAnchor") == fragment:
                    matches.append(value)
                for child in value.values():
                    find_anchor(child)
            elif isinstance(value, list):
                for child in value:
                    find_anchor(child)

        find_anchor(document)
        if len(matches) != 1:
            raise ValueError(f"Unresolved or ambiguous local $ref {ref!r}; use a local #/ pointer")
        return matches[0]
    value = document
    try:
        for part in fragment[1:].split("/") if fragment else []:
            key = part.replace("~1", "/").replace("~0", "~")
            value = value[int(key)] if isinstance(value, list) else value[key]
    except (KeyError, IndexError, ValueError, TypeError) as exc:
        raise ValueError(f"Unresolved local $ref {ref!r}") from exc
    return value


def _resolve(value, document, refs=(), depth=0) -> Any:
    if depth >= _MAX_DEPTH:
        raise ValueError("Local reference resolution exceeds the nesting limit")
    if isinstance(value, list):
        return [_resolve(item, document, refs, depth + 1) for item in value]
    if not isinstance(value, dict):
        return value
    if "$ref" in value:
        ref = value["$ref"]
        if ref in refs:
            return {"$ref": ref}
        target = _resolve(_pointer(document, ref), document, refs + (ref,), depth + 1)
        if not isinstance(target, dict):
            raise ValueError(f"$ref {ref!r} must point to an object")
        return {**target, **_resolve({k: v for k, v in value.items() if k != "$ref"},
                                    document, refs + (ref,), depth + 1)}
    return {key: _resolve(child, document, refs, depth + 1) for key, child in value.items()}


def parse_document(document: dict, source: str = "") -> dict:
    """Validate and normalize a document without mutating it.

    Unsupported/malformed documents raise ValueError. OpenAPI validation requires
    openapi-spec-validator; PyYAML is used by load_inventory for both JSON/YAML.
    Missing operation IDs use the deterministic ``METHOD /path`` fallback.
    """
    if not isinstance(document, dict):
        raise ValueError("API document must be an object")
    is_openapi = "swagger" in document or "openapi" in document
    _check_refs(document, check_references=is_openapi)
    if is_openapi:
        version = document.get("openapi", document.get("swagger"))
        if not isinstance(version, str) or not (
            version == "2.0" or re.fullmatch(r"3\.(?:0|1)\.\d+", version)
        ):
            raise ValueError(f"Unsupported OpenAPI version: {version!r}")
        # The validator cannot locate nested schema anchors in an OpenAPI root.
        validation_document = copy.deepcopy(document)
        anchors, references = {}, []

        def check_local(value, path="#"):
            if isinstance(value, dict):
                for keyword in ("$anchor", "$dynamicAnchor"):
                    if isinstance(value.get(keyword), str):
                        anchors[value[keyword]] = path
                if "$ref" in value:
                    _pointer(document, value["$ref"])
                    references.append(value)
                for key, child in value.items():
                    escaped = str(key).replace("~", "~0").replace("/", "~1")
                    check_local(child, path + "/" + escaped)
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    check_local(child, path + "/" + str(index))

        check_local(validation_document)
        for value in references:
            fragment = unquote(value["$ref"][1:])
            if fragment and not fragment.startswith("/"):
                value["$ref"] = anchors[fragment]
        try:
            from openapi_spec_validator import validate
        except ImportError as exc:
            raise ImportError("OpenAPI parsing requires openapi-spec-validator") from exc
        try:
            validate(validation_document)
        except Exception as exc:
            raise ValueError(f"Invalid OpenAPI document: {exc}") from exc
        inventory = _openapi(_resolve(document, document), source)
    elif isinstance(document.get("info"), dict) and "schema" in document["info"]:
        inventory = _postman(document)
    else:
        raise ValueError("Unsupported document: expected OpenAPI 2/3/3.1 or Postman 2.1")
    ids = [endpoint["operation_id"] for endpoint in inventory["endpoints"]]
    if len(set(ids)) != len(ids):
        raise ValueError("Operation IDs must be unique (including generated IDs)")
    inventory["graph"] = build_graph(inventory["endpoints"])
    return inventory


def _server(servers, source):
    if not servers:
        return ""
    server = servers[0]
    url = server["url"]
    for name, variable in server.get("variables", {}).items():
        url = url.replace("{" + name + "}", str(variable["default"]))
    return urljoin(source, url) if urlsplit(source).scheme in {"http", "https"} else url


def _fields(schema, prefix=""):
    result = []
    if not isinstance(schema, dict):
        return result
    for name, child in schema.get("properties", {}).items():
        field = f"{prefix}.{name}" if prefix else name
        result.append(field)
        result.extend(_fields(child, field))
    if isinstance(schema.get("items"), dict):
        result.extend(_fields(schema["items"], prefix + "[]"))
    for keyword in ("allOf", "anyOf", "oneOf"):
        for child in schema.get(keyword, []):
            result.extend(_fields(child, prefix))
    return list(dict.fromkeys(result))


def _parameter(parameter):
    schema = parameter.get("schema")
    if schema is None and parameter.get("content"):
        schema = next(iter(parameter["content"].values())).get("schema", {})
    if schema is None:
        schema = {key: parameter[key] for key in (
            "type", "format", "items", "enum", "default", "minimum", "maximum",
            "minLength", "maxLength", "pattern", "minItems", "maxItems", "uniqueItems"
        ) if key in parameter}
    if isinstance(schema, dict) and schema.get("type") == "file":
        schema = {"type": "string", "format": "binary"}
    result = {"name": parameter["name"], "in": parameter["in"],
              "required": parameter.get("required", False), "schema": schema}
    for key in ("example", "x-example"):
        if key in parameter:
            result["example"] = parameter[key]
            break
    else:
        if isinstance(schema, dict) and "example" in schema:
            result["example"] = schema["example"]
        elif parameter.get("examples"):
            example = next(iter(parameter["examples"].values()))
            if isinstance(example, dict) and "value" in example:
                result["example"] = example["value"]
    if "content" in parameter:
        result["content"] = parameter["content"]
        media = next(iter(parameter["content"].values()))
        if "example" in media:
            result["example"] = media["example"]
    return result


def _openapi(document, source):
    v2 = document.get("swagger") == "2.0"
    if v2:
        host = document.get("host", "")
        scheme = document.get("schemes", [urlsplit(source).scheme or "https"])[0]
        base = f"{scheme}://{host}{document.get('basePath', '')}" if host else document.get("basePath", "")
        schemes = document.get("securityDefinitions", {})
    else:
        base = _server(document.get("servers"), source)
        schemes = document.get("components", {}).get("securitySchemes", {})
    endpoints = []
    for path, path_item in document.get("paths", {}).items():
        if not path.startswith("/"):
            continue
        for method, operation in path_item.items():
            if method not in _METHODS:
                continue
            merged = {(p["name"], p["in"]): p for p in path_item.get("parameters", [])}
            merged.update({(p["name"], p["in"]): p for p in operation.get("parameters", [])})
            parameters = list(merged.values())
            body = operation.get("requestBody")
            if body is not None:
                body = {"required": body.get("required", False), "content": {
                    kind: {"schema": {}, **media} for kind, media in body.get("content", {}).items()}}
            if v2:
                body_params = [p for p in parameters if p["in"] == "body"]
                forms = [p for p in parameters if p["in"] == "formData"]
                if body_params:
                    param = body_params[0]
                    media = {"schema": param["schema"]}
                    if "x-example" in param:
                        media["example"] = param["x-example"]
                    body = {"required": param.get("required", False), "content": {
                        kind: copy.deepcopy(media) for kind in operation.get("consumes", document.get("consumes", ["application/json"]))}}
                elif forms:
                    properties = {}
                    for param in forms:
                        normalized = _parameter(param)
                        properties[param["name"]] = copy.deepcopy(normalized["schema"])
                        if "example" in normalized:
                            properties[param["name"]]["example"] = normalized["example"]
                    required = [p["name"] for p in forms if p.get("required")]
                    schema = {"type": "object", "properties": properties, "required": required}
                    body = {"required": bool(required), "content": {kind: {"schema": copy.deepcopy(schema)}
                            for kind in operation.get("consumes", document.get("consumes", ["application/x-www-form-urlencoded"]))}}
            response_fields = []
            for status, response in operation.get("responses", {}).items():
                if str(status).startswith("2") or str(status) == "default":
                    response_fields.extend(_fields(response.get("schema", {})))
                    for media in response.get("content", {}).values():
                        response_fields.extend(_fields(media.get("schema", {})))
            endpoint = {"path": path, "method": method.upper(),
                        "operation_id": operation.get("operationId") or f"{method.upper()} {path}",
                        "parameters": [_parameter(p) for p in parameters if p["in"] not in {"body", "formData"}],
                        "request_body": body,
                        "security": operation.get("security", document.get("security", [])),
                        "response_fields": list(dict.fromkeys(response_fields))}
            # Keep overrides without pretending the root server describes every operation.
            if not v2 and ("servers" in operation or "servers" in path_item):
                endpoint["base_url"] = _server(operation.get("servers", path_item.get("servers")), source)
            endpoints.append(endpoint)
    return {"base_url": base, "endpoints": endpoints, "security_schemes": schemes}


def build_graph(endpoints) -> list[dict]:
    """Infer exact path/leaf input links, retaining all ambiguous candidates."""
    edges = []
    seen = set()
    for source in endpoints:
        for target in endpoints:
            if source["operation_id"] == target["operation_id"]:
                continue
            names = [p["name"] for p in target.get("parameters", []) if p["in"] in {"path", "query"}]
            content = (target.get("request_body") or {}).get("content", {})
            media = next((v for k, v in content.items()
                          if k == "application/json" or k.endswith("+json")), {})
            schema = media.get("schema", {})
            if isinstance(schema, dict):
                names.extend(schema.get("required", []))
            for name in names:
                for field in source.get("response_fields", []):
                    if "[]" in field or name not in (field, field.rsplit(".", 1)[-1]):
                        continue
                    key = (source["operation_id"], target["operation_id"], field, name)
                    if key not in seen:
                        seen.add(key)
                        edges.append({"source": key[0], "target": key[1], "field": key[2], "parameter": key[3]})
    return edges


def _variables(items, inherited):
    if not isinstance(items, list):
        raise ValueError("Postman variable must be a list")
    result = dict(inherited)
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("key"), str):
            raise ValueError("Postman variables require a string key")
        if not item.get("disabled") and "value" in item:
            value = item["value"]
            result[item["key"]] = value if isinstance(value, str) else json.dumps(value)
    return result


def _substitute(value: Any, variables: dict) -> Any:
    if isinstance(value, str):
        for _ in range(20):
            replaced = _VARIABLE.sub(lambda match: variables.get(match[1], match[0]), value)
            if replaced == value:
                break
            value = replaced
        return value
    if isinstance(value, list):
        return [_substitute(item, variables) for item in value]
    if isinstance(value, dict):
        return {key: _substitute(child, variables) for key, child in value.items()}
    return value


def _schema(value):
    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, (int, float)):
        return {"type": "integer" if isinstance(value, int) else "number"}
    if isinstance(value, list):
        return {"type": "array", "items": _schema(value[0]) if value else {}}
    if isinstance(value, dict):
        return {"type": "object", "properties": {key: _schema(child) for key, child in value.items()},
                "required": list(value)}
    return {"type": "string"}


def _entries(items, location):
    if not isinstance(items, list):
        raise ValueError(f"Postman {location} entries must be a list")
    result = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("key"), str):
            raise ValueError(f"Postman {location} entries require a string key")
        if item.get("disabled"):
            continue
        parameter = {"name": item["key"], "in": location, "required": True,
                     "schema": _schema(item.get("value", ""))}
        if "value" in item:
            parameter["example"] = item["value"]
        result.append(parameter)
    return result


def _postman_body(body, headers):
    if body is None or body.get("disabled"):
        return None
    mode = body.get("mode")
    content_type = next((str(p.get("example", "")).split(";", 1)[0].strip()
                         for p in headers if p["name"].lower() == "content-type"), "")
    if mode == "raw":
        raw = body.get("raw", "")
        if not isinstance(raw, str):
            raise ValueError("Postman raw body must be a string")
        options = body.get("options", {})
        if not isinstance(options, dict) or not isinstance(options.get("raw", {}), dict):
            raise ValueError("Postman raw body options must be objects")
        language = options.get("raw", {}).get("language")
        is_json = content_type == "application/json" or content_type.endswith("+json") or language == "json"
        try:
            example = json.loads(raw) if is_json else raw
        except json.JSONDecodeError as exc:
            # Unresolved collection variables can legitimately occupy JSON value positions.
            if not _VARIABLE.search(raw):
                raise ValueError(f"Invalid Postman JSON body: {exc}") from exc
            example = raw
        media = content_type or ("application/json" if is_json else "text/plain")
        content = {media: {"schema": _schema(example), "example": example}}
    elif mode in {"urlencoded", "formdata"}:
        entries = _entries(body.get(mode, []), "body")
        properties = {p["name"]: p["schema"] for p in entries}
        if mode == "formdata":
            for item in body.get(mode, []):
                if item.get("type") == "file" and not item.get("disabled"):
                    properties[item["key"]] = {"type": "string", "format": "binary"}
        schema = {"type": "object", "properties": properties, "required": list(properties)}
        example = {p["name"]: p["example"] for p in entries if "example" in p}
        media = content_type or ("multipart/form-data" if mode == "formdata" else "application/x-www-form-urlencoded")
        content = {media: {"schema": schema, "example": example}}
    elif mode == "file":
        content = {content_type or "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}
    elif mode == "graphql":
        example = body.get("graphql", {})
        if not isinstance(example, dict):
            raise ValueError("Postman graphql body must be an object")
        content = {content_type or "application/json": {"schema": _schema(example), "example": example}}
    else:
        raise ValueError(f"Unsupported Postman body mode: {mode!r}")
    return {"required": True, "content": content}


def _postman(document):
    schema_url = document["info"]["schema"]
    if not isinstance(schema_url, str) or not re.fullmatch(
        r"https?://schema\.getpostman\.com/json/collection/v2\.1\.0/collection\.json", schema_url
    ):
        raise ValueError("Unsupported Postman version; expected collection v2.1.0")
    if not isinstance(document.get("info", {}).get("name"), str):
        raise ValueError("Postman collection info.name must be a string")
    endpoints, schemes = [], {}
    base_url = ""

    def security(auth):
        if auth is None:
            return []
        if not isinstance(auth, dict) or not isinstance(auth.get("type"), str):
            raise ValueError("Postman auth must contain a type")
        kind = auth["type"]
        if kind == "noauth":
            return []
        metadata: dict[str, Any] = {"x-postman-auth": copy.deepcopy(auth)}
        if kind in {"basic", "bearer", "digest"}:
            metadata.update(type="http", scheme=kind)
        elif kind == "apikey":
            entries = auth.get("apikey", [])
            if not isinstance(entries, list) or any(not isinstance(e, dict) for e in entries):
                raise ValueError("Postman apikey auth must be a list of entries")
            values = {entry.get("key"): entry.get("value") for entry in entries}
            metadata.update(type="apiKey", name=values.get("key", ""), **{"in": values.get("in", "header")})
        else:
            metadata["type"] = kind
        for name, existing in schemes.items():
            if existing == metadata:
                return [{name: []}]
        name = f"postman_{kind}_{len(schemes) + 1}"
        schemes[name] = metadata
        return [{name: []}]

    def walk(items, inherited, auth, names):
        nonlocal base_url
        if not isinstance(items, list):
            raise ValueError("Postman item must be a list")
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                raise ValueError("Postman item must be an object")
            variables = _variables(item.get("variable", []), inherited)
            current_auth = item.get("auth") or auth
            trail = names + [str(index)]
            if "item" in item:
                if "request" in item:
                    raise ValueError("Postman item cannot contain both request and folder items")
                walk(item["item"], variables, current_auth, trail)
                continue
            request = item.get("request")
            if isinstance(request, str):
                request = {"method": "GET", "url": request}
            if not isinstance(request, dict):
                raise ValueError("Postman request must be an object or URL string")
            request = _substitute(request, variables)
            method = request.get("method")
            if not isinstance(method, str) or not re.fullmatch(r"[A-Za-z]+", method):
                raise ValueError("Postman request requires a valid method")
            url = request.get("url")
            if not isinstance(url, (str, dict)):
                raise ValueError("Postman request requires a URL string or object")
            url_object = url if isinstance(url, dict) else {}
            raw = url_object.get("raw", "") if url_object else url
            if not raw and url_object:
                host = url_object.get("host", "")
                path = url_object.get("path", [])
                for part in (host, path):
                    if not isinstance(part, (str, list)) or (
                        isinstance(part, list) and any(not isinstance(segment, str) for segment in part)
                    ):
                        raise ValueError("Postman URL host/path must be strings or lists of strings")
                host = ".".join(host) if isinstance(host, list) else host
                path = "/".join(path) if isinstance(path, list) else path
                port = url_object.get("port")
                authority = f"{host}:{port}" if port else host
                raw = f"{url_object.get('protocol', 'https')}://{authority}/{path}"
            if not isinstance(raw, str) or not raw:
                raise ValueError("Postman URL must not be empty")
            parsed = urlsplit(raw)
            if parsed.scheme and parsed.scheme not in {"http", "https"}:
                raise ValueError("Postman URLs must use HTTP(S)")
            if parsed.scheme and not parsed.netloc:
                raise ValueError("Postman HTTP(S) URL requires a host")
            endpoint_base = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else ""
            if not endpoints:
                base_url = endpoint_base
            path = parsed.path or "/"
            if not path.startswith("/"):
                path = "/" + path
            path = re.sub(r"(?<=/):([\w-]+)", r"{\1}", path)
            path_parameters = _entries(url_object.get("variable", []), "path")
            for name in re.findall(r"(?<!\{)\{([^{}]+)\}(?!\})", path):
                if name not in {p["name"] for p in path_parameters}:
                    path_parameters.append({"name": name, "in": "path", "required": True, "schema": {"type": "string"}})
            if "query" in url_object:
                query = _entries(url_object["query"], "query")
            else:
                # Preserve the distinction between a bare flag and an explicit empty value.
                query = []
                for pair in parsed.query.split("&") if parsed.query else []:
                    name, separator, value = pair.partition("=")
                    entry = {"key": unquote(name.replace("+", " "))}
                    if separator:
                        entry["value"] = unquote(value.replace("+", " "))
                    query.extend(_entries([entry], "query"))
            headers = _entries(request.get("header", []), "header")
            fields = []
            responses = item.get("response", [])
            if not isinstance(responses, list):
                raise ValueError("Postman response must be a list")
            for response in responses:
                if not isinstance(response, dict):
                    raise ValueError("Postman response must be an object")
                code = response.get("code", 200)
                if not isinstance(code, int) or not 200 <= code < 300:
                    continue
                try:
                    value = json.loads(_substitute(response.get("body", ""), variables))
                except (ValueError, TypeError):
                    continue
                fields.extend(_fields(_schema(value)))
            body = request.get("body")
            if body is not None and not isinstance(body, dict):
                raise ValueError("Postman body must be an object")
            endpoint = {"path": path, "method": method.upper(),
                        "operation_id": "postman_" + "_".join(trail),
                        "parameters": path_parameters + query + headers,
                        "request_body": _postman_body(body, headers),
                        "security": security(_substitute(request.get("auth") or current_auth, variables)),
                        "response_fields": list(dict.fromkeys(fields))}
            if endpoint_base != base_url:
                endpoint["base_url"] = endpoint_base
            endpoints.append(endpoint)

    variables = _variables(document.get("variable", []), {})
    walk(document.get("item"), variables, document.get("auth"), [])
    return {"base_url": base_url, "endpoints": endpoints, "security_schemes": schemes}
