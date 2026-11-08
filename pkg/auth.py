"""Pluggable, in-memory authentication for guarded LedgerProbe scans.

Secrets are deliberately awkward to print or serialize.  A Secret can only be
opened with ``reveal()`` at the request-building boundary; all normal string
conversions produce ``***``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import stat
import time
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit, urljoin

import httpx
import yaml

from .guardrails import AUTH_FLOW

__all__ = [
    "AuthError", "AuthManager", "Secret", "SecretResolver",
    "load_auth_config", "redact", "register_secret",
]

_SECRET_REF = re.compile(r"^(env|file|vault|aws):.+$")
_HEADER = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_CREDENTIAL_KEYS = {
    "password", "secret", "token", "authorization", "api_key", "apikey",
    "client_secret", "client_id",
}


class AuthError(ValueError):
    """A configuration or credential-flow failure with no secret material."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason
        self.message = message


class Redactor:
    def __init__(self) -> None:
        self._values: set[str] = set()
        self._installed = False

    def register(self, value: str) -> None:
        if value and value != "***":
            self._values.add(value)
            self._install()

    def redact(self, value) -> str:
        if isinstance(value, Secret):
            return "***"
        text = str(value)
        for secret in sorted(self._values, key=len, reverse=True):
            if secret in text:
                text = text.replace(secret, "[REDACTED]")
        return text

    def _install(self) -> None:
        if self._installed:
            return
        class _Filter(logging.Filter):
            def filter(self, record):
                record.msg = redact(record.msg)
                if record.args:
                    if isinstance(record.args, dict):
                        record.args = {key: redact(value) for key, value in record.args.items()}
                    else:
                        record.args = tuple(redact(value) for value in record.args)
                return True
        logging.getLogger().addFilter(_Filter())
        self._installed = True


_REDACTOR = Redactor()


def register_secret(value: str) -> None:
    _REDACTOR.register(value)


def redact(value) -> str:
    return _REDACTOR.redact(value)


def redact_data(value):
    """Redact strings recursively while preserving JSON-compatible structures."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {redact_data(key): redact_data(child) for key, child in value.items()}
    if isinstance(value, list):
        return [redact_data(child) for child in value]
    return value


class Secret:
    """An in-memory secret whose normal representations are always ``***``."""

    __slots__ = ("_value",)

    def __init__(self, value: str):
        if not isinstance(value, str):
            raise TypeError("secret values must be strings")
        self._value = value
        register_secret(value)

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "***"

    def __str__(self) -> str:
        return "***"

    def __format__(self, spec: str) -> str:
        return "***"

    def __reduce__(self):
        raise TypeError("Secret values cannot be serialized")


def _split(ref: str) -> tuple[str, str, str]:
    if not isinstance(ref, str) or not _SECRET_REF.fullmatch(ref):
        raise AuthError("invalid_secret_ref",
                        "secret references must use env:, file:, vault:, or aws: syntax")
    scheme, rest = ref.split(":", 1)
    if scheme == "env":
        if not rest or "#" in rest:
            raise AuthError("invalid_secret_ref", "env secret references must be env:NAME")
        return scheme, rest, ""
    path, separator, key = rest.rpartition("#")
    if not separator or not path or not key:
        raise AuthError("invalid_secret_ref",
                        f"{scheme} secret references require <path>#<key>")
    return scheme, path, key


def _dotenv(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if key:
            values[key] = value
    return values


class SecretResolver:
    """Resolve env/file/Vault/AWS references into Secret objects."""

    def __init__(self, transport=None, timeout: float = 5.0):
        self.transport = transport
        self.timeout = timeout

    async def resolve(self, ref: str) -> Secret:
        scheme, path, key = _split(ref)
        if scheme == "env":
            if path not in os.environ:
                raise AuthError("secret_unavailable", f"environment variable {path} is not set")
            return Secret(os.environ[path])
        if scheme == "file":
            return Secret(await asyncio.to_thread(self._file, path, key))
        if scheme == "vault":
            return Secret(await self._vault(path, key))
        if scheme == "aws":
            return Secret(await asyncio.to_thread(self._aws, path, key))
        raise AssertionError("unreachable")

    @staticmethod
    def _file(path: str, key: str) -> str:
        file = Path(path)
        try:
            info = file.stat()
        except OSError:
            raise AuthError("secret_unavailable", f"secret file {path} is unavailable") from None
        if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
            raise AuthError("secret_file_permissions",
                            f"secret file {path} is readable by group/other; use chmod 600")
        try:
            text = file.read_text(encoding="utf-8")
        except OSError:
            raise AuthError("secret_unavailable", f"secret file {path} is unreadable") from None
        values = _dotenv(text)
        stripped = text.lstrip()
        if stripped.startswith("{"):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                raise AuthError("secret_unavailable",
                                f"secret file {path} is not valid JSON") from None
            if not isinstance(parsed, dict) or key not in parsed:
                raise AuthError("secret_unavailable", f"secret key {key} is absent from {path}")
            value = parsed[key]
        else:
            if key not in values:
                raise AuthError("secret_unavailable", f"secret key {key} is absent from {path}")
            value = values[key]
        if not isinstance(value, str):
            raise AuthError("secret_unavailable", f"secret key {key} is not a string")
        return value

    async def _vault(self, path: str, field: str) -> str:
        address = os.environ.get("VAULT_ADDR", "").rstrip("/")
        token = os.environ.get("VAULT_TOKEN")
        if not address or not token:
            raise AuthError("secret_unavailable", "VAULT_ADDR and VAULT_TOKEN must be set")
        url = f"{address}/v1/{path.lstrip('/')}"
        headers = {"X-Vault-Token": token}
        try:
            async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport) as client:
                response = await client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            raise AuthError("secret_unavailable", f"Vault request failed ({type(exc).__name__})") from None
        if response.status_code != 200:
            raise AuthError("secret_unavailable",
                            f"Vault returned HTTP {response.status_code} for the requested path")
        try:
            payload = response.json()
            value = payload["data"]["data"][field]
        except (ValueError, TypeError, KeyError):
            raise AuthError("secret_unavailable",
                            f"Vault field {field} was not found in the requested path") from None
        return _string_secret(value, "vault")

    @staticmethod
    def _aws(secret_id: str, key: str) -> str:
        try:
            import boto3  # type: ignore[import-not-found]
            from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-not-found]
        except ImportError:
            raise AuthError(
                "secret_unavailable",
                "AWS Secrets Manager support is optional; install ledgerprobe[aws]",
            ) from None
        try:
            client = boto3.client("secretsmanager")
            response = client.get_secret_value(SecretId=secret_id)
            text = response.get("SecretString")
            payload = json.loads(text) if text else {}
            value = payload[key]
        except (BotoCoreError, ClientError, ValueError, TypeError, KeyError):
            raise AuthError("secret_unavailable",
                            f"AWS secret {secret_id} did not contain JSON key {key}") from None
        return _string_secret(value, "aws")


def _string_secret(value, provider: str) -> str:
    if not isinstance(value, str):
        raise AuthError("secret_unavailable", f"{provider} secret field is not a string")
    return value


def _mapping(value, allowed, required=(), label="auth"):
    if not isinstance(value, dict):
        raise AuthError("invalid_auth_config", f"{label} must be an object")
    unknown = set(value) - set(allowed)
    missing = set(required) - set(value)
    if unknown or missing:
        raise AuthError("invalid_auth_config",
                        f"{label} has missing or unknown fields")
    return value


def _secret_ref(value, field: str) -> str:
    if not isinstance(value, str) or not _SECRET_REF.fullmatch(value):
        raise AuthError("invalid_auth_config", f"{field} must be a secret reference")
    return value


def _reject_inline(value, path: str = "params") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            lower = key.lower()
            if key.endswith("_ref"):
                _secret_ref(child, f"{path}.{key}")
            elif lower in _CREDENTIAL_KEYS:
                if not isinstance(child, str) or not _SECRET_REF.fullmatch(child):
                    raise AuthError("inline_credential",
                                    f"{path}.{key} must use a secret reference")
            _reject_inline(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_inline(child, f"{path}[{index}]")


def _command(value, label: str):
    _mapping(value, {"argv", "timeout", "env"}, {"argv"}, label)
    argv = value["argv"]
    if (not isinstance(argv, list) or not argv
            or any(not isinstance(part, str) or not part for part in argv)):
        raise AuthError("invalid_auth_config", f"{label}.argv must be a nonempty string list")
    timeout = value.get("timeout", 30)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise AuthError("invalid_auth_config", f"{label}.timeout must be positive")
    env = value.get("env", [])
    if (not isinstance(env, list) or any(not isinstance(name, str) or not name for name in env)):
        raise AuthError("invalid_auth_config", f"{label}.env must be a string list")
    return {"argv": list(argv), "timeout": float(timeout), "env": list(env)}


def _identity(value, name: str):
    _mapping(value, {"provider", "params", "environment", "refresh_on_401"},
             {"provider", "params", "environment"}, f"identity {name}")
    provider = value["provider"]
    if provider not in {"static_header", "oauth2_client_credentials", "login_request", "script"}:
        raise AuthError("invalid_auth_config", f"identity {name}.provider is unsupported")
    environment = value["environment"]
    if environment not in {"lab", "staging", "production"}:
        raise AuthError("invalid_auth_config",
                        f"identity {name}.environment must be lab, staging or production")
    refresh = value.get("refresh_on_401", False)
    if not isinstance(refresh, bool):
        raise AuthError("invalid_auth_config", f"identity {name}.refresh_on_401 must be boolean")
    params = value["params"]
    if not isinstance(params, dict):
        raise AuthError("invalid_auth_config", f"identity {name}.params must be an object")
    _reject_inline(params, f"identity {name}.params")
    if provider == "static_header":
        _mapping(params, {"header", "value_ref"}, {"header", "value_ref"}, f"identity {name}.params")
        if not isinstance(params["header"], str) or not _HEADER.fullmatch(params["header"]):
            raise AuthError("invalid_auth_config", f"identity {name}.params.header is invalid")
        _secret_ref(params["value_ref"], f"identity {name}.params.value_ref")
    elif provider == "oauth2_client_credentials":
        _mapping(params, {"token_url", "client_id_ref", "client_secret_ref", "scope"},
                 {"token_url", "client_id_ref", "client_secret_ref", "scope"},
                 f"identity {name}.params")
        try:
            parsed = urlsplit(params["token_url"])
        except (TypeError, ValueError):
            parsed = None
        if parsed is None or parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise AuthError("invalid_auth_config", f"identity {name}.params.token_url is invalid")
        _secret_ref(params["client_id_ref"], f"identity {name}.params.client_id_ref")
        _secret_ref(params["client_secret_ref"], f"identity {name}.params.client_secret_ref")
        if not isinstance(params["scope"], str) or not params["scope"]:
            raise AuthError("invalid_auth_config", f"identity {name}.params.scope is invalid")
    elif provider == "login_request":
        allowed = {"method", "path", "body", "body_format", "token_json_path", "token_header",
                   "token_cookie", "expiry_json_path", "header_format"}
        _mapping(params, allowed, {"method", "path", "body"}, f"identity {name}.params")
        if params["method"] not in {"GET", "POST", "PUT", "PATCH"}:
            raise AuthError("invalid_auth_config", f"identity {name}.params.method is invalid")
        if not isinstance(params["path"], str) or not params["path"].startswith("/"):
            raise AuthError("invalid_auth_config", f"identity {name}.params.path is invalid")
        if not isinstance(params["body"], dict):
            raise AuthError("invalid_auth_config", f"identity {name}.params.body must be an object")
        if params.get("body_format", "json") not in {"json", "form"}:
            raise AuthError("invalid_auth_config",
                            f"identity {name}.params.body_format must be json or form")
        extractors = [key for key in ("token_json_path", "token_header", "token_cookie")
                      if key in params]
        if len(extractors) != 1:
            raise AuthError("invalid_auth_config",
                            f"identity {name}.params needs exactly one token extractor")
        for key in ("token_json_path", "token_header", "token_cookie", "expiry_json_path"):
            if key in params and (not isinstance(params[key], str) or not params[key]):
                raise AuthError("invalid_auth_config", f"identity {name}.params.{key} is invalid")
        if "header_format" in params and (not isinstance(params["header_format"], str)
                                          or "{token}" not in params["header_format"]):
            raise AuthError("invalid_auth_config",
                            f"identity {name}.params.header_format needs {{token}}")
    else:
        _mapping(params, {"argv", "timeout", "env"}, {"argv"}, f"identity {name}.params")
        _command(params, f"identity {name}.params")
    normalized = dict(value)
    normalized["refresh_on_401"] = refresh
    normalized["params"] = dict(params)
    return normalized


def load_auth_config(path) -> dict:
    """Load a strict ledgerprobe-auth.yaml document."""
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        raise AuthError("invalid_auth_config", "auth configuration could not be read") from None
    _mapping(data, {"schema_version", "identities", "setup", "teardown", "extra_headers"},
             {"schema_version", "identities"}, "auth configuration")
    if data["schema_version"] != "ledgerprobe-auth/1":
        raise AuthError("invalid_auth_config", "auth schema_version must be ledgerprobe-auth/1")
    identities = data["identities"]
    if not isinstance(identities, dict) or not identities:
        raise AuthError("invalid_auth_config", "identities must be a nonempty object")
    result = {"schema_version": "ledgerprobe-auth/1", "identities": {}}
    for name, value in identities.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise AuthError("invalid_auth_config", "identity names must be safe identifiers")
        result["identities"][name] = _identity(value, name)
    if "extra_headers" in data:
        headers = data["extra_headers"]
        if not isinstance(headers, dict):
            raise AuthError("invalid_auth_config", "extra_headers must be an object")
        result["extra_headers"] = {}
        for key, value in headers.items():
            if (not isinstance(key, str) or not _HEADER.fullmatch(key) or not isinstance(value, str)
                    or not value or len(value) > 256 or any(char in value for char in "\r\n")
                    or value.lower().startswith(("bearer ", "basic ", "token "))
                    or re.search(r"(?i)(secret|password|api[-_]?key|authorization)", key)
                    or re.fullmatch(r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", value)):
                raise AuthError("invalid_auth_config",
                                "extra_headers may contain only non-secret identification values")
            result["extra_headers"][key] = value
    for hook in ("setup", "teardown"):
        if hook in data:
            result[hook] = _command(data[hook], hook)
    return result


def _lookup(value, path: str):
    current = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _substitute(value, variables):
    if isinstance(value, dict):
        return {key: _substitute(child, variables) for key, child in value.items()}
    if isinstance(value, list):
        return [_substitute(child, variables) for child in value]
    if isinstance(value, str):
        match = re.fullmatch(r"\{\{\s*([\w.-]+)\s*\}\}", value)
        if match and match.group(1) in variables:
            return variables[match.group(1)]
    return value


def _loopback(host: str) -> bool:
    if host in {"localhost", "::1"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class AuthManager:
    """Resolve identities and mediate refresh without persisting credentials."""

    def __init__(self, config: dict, variables: dict, base_url: str, client,
                 allowed_hosts=(), resolver: SecretResolver | None = None):
        self.config = config
        self.variables = dict(variables)
        self.base_url = base_url.rstrip("/")
        self.client = client
        self.allowed_hosts = {str(host).lower() for host in allowed_hosts}
        self.resolver = resolver or SecretResolver()
        self.contexts: dict[str, dict[str, str]] = {}
        self.states: dict[str, dict] = {}
        self.attempts = defaultdict(int)
        self.notes: set[str] = set()
        self.error: AuthError | None = None
        self._teardown_done = False

    def _identity(self, name: str) -> dict:
        try:
            return self.config["identities"][name]
        except KeyError:
            raise AuthError("auth_identity_unknown", f"identity {name} is not configured") from None

    def _host_allowed(self, url: str) -> None:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise AuthError("auth_host_not_allowed", "auth endpoint must be an HTTP(S) URL")
        host = parsed.hostname.lower()
        target = urlsplit(self.base_url).hostname
        if host == (target or "").lower() or _loopback(host) or host in self.allowed_hosts:
            return
        raise AuthError("auth_host_not_allowed",
                        f"auth host {host} is not in the allowed-hosts list")

    async def _run_command(self, command: dict, label: str) -> dict:
        env = {name: os.environ[name] for name in command["env"] if name in os.environ}
        try:
            process = await asyncio.create_subprocess_exec(
                *command["argv"], stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, env=env,
            )
            stdout, _stderr = await asyncio.wait_for(process.communicate(),
                                                     timeout=command["timeout"])
        except asyncio.TimeoutError:
            try:
                process.kill()
                await process.wait()
            except (NameError, ProcessLookupError):
                pass
            raise AuthError(f"{label}_failed", f"{label} command timed out") from None
        except OSError:
            raise AuthError(f"{label}_failed", f"{label} command could not start") from None
        if len(stdout) > 65536:
            raise AuthError(f"{label}_failed", f"{label} output exceeded 64 KB")
        if process.returncode != 0:
            raise AuthError(f"{label}_failed",
                            f"{label} command exited {process.returncode}")
        try:
            payload = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AuthError(f"{label}_failed", f"{label} output was not JSON") from None
        if not isinstance(payload, dict):
            raise AuthError(f"{label}_failed", f"{label} output must be a JSON object")
        return payload

    async def setup(self) -> None:
        if "setup" in self.config:
            payload = await self._run_command(self.config["setup"], "setup")
            self.variables.update(payload)

    async def teardown(self) -> None:
        if self._teardown_done:
            return
        self._teardown_done = True
        if "teardown" in self.config:
            await self._run_command(self.config["teardown"], "teardown")

    async def initialize(self) -> dict[str, dict[str, str]]:
        try:
            for name in self.config["identities"]:
                await self._resolve(name)
        except AuthError as exc:
            self.error = exc
            raise
        return self.contexts

    async def _resolve(self, name: str) -> None:
        identity = self._identity(name)
        provider, params = identity["provider"], identity["params"]
        if provider == "static_header":
            secret = await self.resolver.resolve(params["value_ref"])
            self.contexts[name] = {params["header"]: secret.reveal()}
            self.states[name] = {"expiry": None}
            return
        if provider == "oauth2_client_credentials":
            await self._oauth(name, params)
            return
        if provider == "login_request":
            await self._login(name, params)
            return
        if provider == "script":
            payload = await self._run_command(
                {**params, "timeout": params.get("timeout", 30), "env": params.get("env", [])},
                "script",
            )
            headers = payload.get("headers")
            if (not isinstance(headers, dict) or not headers
                    or any(not isinstance(key, str) or not isinstance(value, str)
                           or not _HEADER.fullmatch(key) or "\n" in value or "\r" in value
                           for key, value in headers.items())):
                raise AuthError("auth_failed", "script provider returned invalid headers")
            for key in headers.values():
                register_secret(key)
            self.contexts[name] = dict(headers)
            expiry = payload.get("expires_in")
            self.states[name] = {"expiry": None if expiry is None else
                                 time.monotonic() + float(expiry)}
            return
        raise AssertionError("unreachable")

    async def _oauth(self, name: str, params: dict) -> None:
        client_id = await self.resolver.resolve(params["client_id_ref"])
        client_secret = await self.resolver.resolve(params["client_secret_ref"])
        self._host_allowed(params["token_url"])
        self.attempts[name] += 1
        if self.attempts[name] > 3:
            raise AuthError("auth_failed", "authentication attempt limit reached")
        try:
            response = await self.client.request(
                "POST", params["token_url"],
                data={"grant_type": "client_credentials", "scope": params["scope"]},
                auth=httpx.BasicAuth(client_id.reveal(), client_secret.reveal()),
                headers={"Accept": "application/json"}, auth_flow=AUTH_FLOW,
            )
        except httpx.HTTPError as exc:
            raise AuthError("auth_failed", f"token request failed ({type(exc).__name__})") from None
        if response.status_code in {400, 401, 403}:
            raise AuthError("auth_failed", f"token endpoint rejected the client ({response.status_code})")
        if not 200 <= response.status_code < 300:
            raise AuthError("auth_failed", f"token endpoint returned {response.status_code}")
        try:
            payload = response.json()
        except ValueError:
            raise AuthError("auth_failed", "token endpoint returned unparseable JSON") from None
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise AuthError("auth_failed", "token endpoint did not return access_token")
        self._register_token(token)
        expires = payload.get("expires_in", 3600)
        try:
            seconds = float(expires)
        except (TypeError, ValueError):
            raise AuthError("auth_failed", "token expiry was invalid") from None
        self.contexts[name] = {"Authorization": "Bearer " + token}
        self.states[name] = {"expiry": time.monotonic() + max(0.0, seconds - 30.0)}

    async def _login(self, name: str, params: dict) -> None:
        body = {}
        for key, value in params["body"].items():
            if key.endswith("_ref"):
                body[key[:-4]] = (await self.resolver.resolve(value)).reveal()
            else:
                body[key] = _substitute(value, self.variables)
        url = urljoin(self.base_url + "/", params["path"].lstrip("/"))
        self._host_allowed(url)
        self.attempts[name] += 1
        if self.attempts[name] > 3:
            raise AuthError("auth_failed", "authentication attempt limit reached")
        payload_body = ({"data": body} if params.get("body_format", "json") == "form"
                        else {"json": body})
        try:
            response = await self.client.request(
                params["method"], url, headers={"Accept": "application/json"},
                auth_flow=AUTH_FLOW, **payload_body,
            )
        except httpx.HTTPError as exc:
            raise AuthError("auth_failed", f"login request failed ({type(exc).__name__})") from None
        if response.status_code in {400, 401, 403}:
            raise AuthError("auth_failed", f"login endpoint rejected credentials ({response.status_code})")
        if not 200 <= response.status_code < 300:
            raise AuthError("auth_failed", f"login endpoint returned {response.status_code}")
        try:
            payload = response.json()
        except ValueError:
            payload = None
        if "token_json_path" in params:
            token = _lookup(payload, params["token_json_path"])
        elif "token_header" in params:
            token = response.headers.get(params["token_header"])
        else:
            token = self._cookie(response, params["token_cookie"])
        if not isinstance(token, str) or not token:
            raise AuthError("auth_failed", "login response did not contain a token")
        self._register_token(token)
        expiry = None
        if "expiry_json_path" in params:
            raw = _lookup(payload, params["expiry_json_path"])
            try:
                expiry = time.monotonic() + max(0.0, float(raw) - 30.0)
            except (TypeError, ValueError):
                raise AuthError("auth_failed", "login expiry was invalid") from None
        fmt = params.get("header_format", "Bearer {token}")
        self.contexts[name] = {"Authorization": fmt.format(token=token)}
        self.states[name] = {"expiry": expiry}

    @staticmethod
    def _cookie(response, name: str):
        for header in response.headers.get_list("set-cookie"):
            first, _, _rest = header.partition(";")
            key, separator, value = first.partition("=")
            if separator and key.strip() == name:
                return value.strip()
        return None

    @staticmethod
    def _register_token(token: str) -> None:
        register_secret(token)

    def headers(self, name: str | None) -> dict[str, str]:
        if name is None:
            return {}
        return dict(self.contexts.get(name, {}))

    def can_refresh_on_401(self, name: str | None) -> bool:
        if name is None:
            return False
        try:
            return bool(self._identity(name).get("refresh_on_401", False))
        except AuthError:
            return False

    async def ensure(self, name: str | None) -> None:
        if name is None:
            return
        state = self.states.get(name)
        if state and state.get("expiry") is not None and time.monotonic() >= state["expiry"]:
            await self.refresh(name)

    async def refresh(self, name: str | None) -> None:
        if name is None:
            return
        identity = self._identity(name)
        if identity["provider"] == "static_header":
            return
        if self.attempts[name] >= 3:
            raise AuthError("auth_failed", "authentication attempt limit reached")
        await self._resolve(name)
        self.notes.add("auth_refreshed")
