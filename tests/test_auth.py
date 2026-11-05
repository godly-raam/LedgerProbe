from __future__ import annotations

import asyncio
import json
import logging
import os
import stat
import sys
import tempfile
import traceback
import unittest
from io import StringIO
from pathlib import Path

import httpx
import yaml

from pkg.auth import (AuthError, AuthManager, Secret, SecretResolver, load_auth_config,
                      redact)
from pkg.guardrails import GuardedClient
from pkg.rules import run_rules

ROOT = Path(__file__).parent.parent


def _yaml(data) -> dict:
    return yaml.safe_load(yaml.safe_dump(data))


def _login(*, refresh=False, expiry=True):
    body = {"username": "{{owner}}", "password_ref": "env:AUTH_TEST_PASSWORD"}
    return {
        "provider": "login_request",
        "environment": "staging",
        "refresh_on_401": refresh,
        "params": {
            "method": "POST", "path": "/login", "body": body,
            "token_json_path": "access_token",
            **({"expiry_json_path": "expires_in"} if expiry else {}),
            "header_format": "Bearer {token}",
        },
    }


def _config(identity, setup=None, teardown=None):
    data = {"schema_version": "ledgerprobe-auth/1", "identities": {"owner": identity}}
    if setup is not None:
        data["setup"] = setup
    if teardown is not None:
        data["teardown"] = teardown
    return _yaml(data)


def _endpoint():
    return {
        "path": "/items/1", "method": "GET", "operation_id": "getItem",
        "parameters": [], "request_body": {}, "security": [], "response_fields": [],
    }


def _inventory():
    return {"base_url": "https://target.test", "endpoints": [_endpoint()], "graph": []}


def _rule():
    return {
        "id": "auth-rule", "name": "Auth request", "severity": "high",
        "owasp_category": "API1:2023", "cvss_score": 5.0,
        "target_endpoints": [{"path": "/items/1", "method": "GET"}],
        "auth_contexts": {"primary": "owner", "forbidden": "owner"},
        "assertions": [{"type": "status_code", "expected": 200}],
    }


async def _manager(config, handler, *, variables=None, allowed_hosts=()):
    client = GuardedClient(max_rps=10000, timeout=5, transport=httpx.MockTransport(handler))
    manager = AuthManager(config, variables or {}, "https://target.test", client,
                          allowed_hosts=allowed_hosts)
    return client, manager


class AuthProviderTests(unittest.IsolatedAsyncioTestCase):
    async def test_auth_host_must_be_allowed(self):
        identity = {
            "provider": "oauth2_client_credentials", "environment": "staging",
            "params": {"token_url": "https://idp.other.test/token",
                       "client_id_ref": "env:AUTH_TEST_ID",
                       "client_secret_ref": "env:AUTH_TEST_SECRET", "scope": "read"},
        }
        os.environ["AUTH_TEST_ID"] = "client"
        os.environ["AUTH_TEST_SECRET"] = "SECRET"
        try:
            async with GuardedClient() as client:
                manager = AuthManager(_config(identity), {}, "https://target.test", client)
                with self.assertRaises(AuthError) as caught:
                    await manager.initialize()
                self.assertEqual(caught.exception.reason, "auth_host_not_allowed")
        finally:
            os.environ.pop("AUTH_TEST_ID", None)
            os.environ.pop("AUTH_TEST_SECRET", None)

    async def test_401_without_refresh_is_baseline_unauthorized(self):
        calls = []

        def handler(request):
            calls.append(request)
            if request.url.path == "/login":
                return httpx.Response(200, json={"access_token": "T", "expires_in": 60})
            return httpx.Response(401, json={})

        os.environ["AUTH_TEST_PASSWORD"] = "PASS"
        try:
            async with GuardedClient(transport=httpx.MockTransport(handler)) as client:
                manager = AuthManager(_config(_login(refresh=False)), {}, "https://target.test", client)
                await manager.initialize()
                results = await run_rules(_inventory(), [_rule()], client,
                                          contexts=manager.contexts, variables={},
                                          auth_manager=manager)
                self.assertEqual(results[0]["reason"], "baseline_unauthorized")
                self.assertEqual(len([r for r in calls if r.url.path == "/login"]), 1)
        finally:
            os.environ.pop("AUTH_TEST_PASSWORD", None)

    async def test_attempt_cap(self):
        def handler(request):
            return httpx.Response(200, json={"access_token": "T", "expires_in": 60})

        os.environ["AUTH_TEST_PASSWORD"] = "PASS"
        try:
            async with GuardedClient(transport=httpx.MockTransport(handler)) as client:
                manager = AuthManager(_config(_login()), {}, "https://target.test", client)
                await manager.initialize()
                await manager.refresh("owner")
                await manager.refresh("owner")
                with self.assertRaises(AuthError) as caught:
                    await manager.refresh("owner")
                self.assertEqual(caught.exception.reason, "auth_failed")
        finally:
            os.environ.pop("AUTH_TEST_PASSWORD", None)

    async def test_unauthenticated_control_has_no_auth_header(self):
        seen = []

        def handler(request):
            seen.append(request.headers.get("authorization"))
            return httpx.Response(200, json={"id": "OWNER"})

        os.environ["AUTH_TEST_OWNER"] = "OWNER-TOKEN"
        os.environ["AUTH_TEST_OTHER"] = "OTHER-TOKEN"
        try:
            owner = {"provider": "static_header", "environment": "lab",
                     "params": {"header": "Authorization", "value_ref": "env:AUTH_TEST_OWNER"}}
            other = {"provider": "static_header", "environment": "lab",
                     "params": {"header": "Authorization", "value_ref": "env:AUTH_TEST_OTHER"}}
            document = _yaml({"schema_version": "ledgerprobe-auth/1",
                              "identities": {"owner": owner, "other": other}})
            selected = _rule()
            selected["auth_contexts"] = {"primary": "owner", "forbidden": "other"}
            selected["leak_detection"] = {"canaries": ["OWNER"], "min_unique_leaf_values": 1,
                                          "ignore_fields": []}
            selected["controls"] = {"nonexistent_object": False, "unauthenticated": True}
            selected.pop("assertions")
            async with GuardedClient(transport=httpx.MockTransport(handler)) as client:
                manager = AuthManager(document, {}, "https://target.test", client)
                await manager.initialize()
                await run_rules(_inventory(), [selected], client, contexts=manager.contexts,
                                variables={}, auth_manager=manager)
                self.assertIn(None, seen)
        finally:
            os.environ.pop("AUTH_TEST_OWNER", None)
            os.environ.pop("AUTH_TEST_OTHER", None)

    async def test_static_env_and_redaction(self):
        os.environ["AUTH_TEST_STATIC"] = "STATIC-SECRET-7391528"
        try:
            config = _config({
                "provider": "static_header", "environment": "lab",
                "params": {"header": "Authorization", "value_ref": "env:AUTH_TEST_STATIC"},
            })
            async with GuardedClient() as client:
                manager = AuthManager(config, {}, "https://target.test", client)
                await manager.initialize()
                self.assertEqual(manager.headers("owner"), {"Authorization": "STATIC-SECRET-7391528"})
        finally:
            os.environ.pop("AUTH_TEST_STATIC", None)

    async def test_oauth_client_credentials_and_caching(self):
        calls = []

        def handler(request):
            calls.append(request)
            self.assertEqual(request.url.path, "/token")
            return httpx.Response(200, json={"access_token": "OAUTH-SECRET-7391528",
                                              "expires_in": 3600})

        identity = {
            "provider": "oauth2_client_credentials", "environment": "staging",
            "params": {"token_url": "https://idp.test/token",
                       "client_id_ref": "env:AUTH_TEST_ID",
                       "client_secret_ref": "env:AUTH_TEST_SECRET", "scope": "read"},
        }
        os.environ["AUTH_TEST_ID"] = "client"
        os.environ["AUTH_TEST_SECRET"] = "CLIENT-SECRET-7391528"
        try:
            async with GuardedClient(transport=httpx.MockTransport(handler)) as client:
                manager = AuthManager(_config(identity), {}, "https://target.test", client,
                                      allowed_hosts=("idp.test",))
                await manager.initialize()
                await manager.ensure("owner")
                self.assertEqual(len(calls), 1)
                self.assertEqual(manager.headers("owner")["Authorization"],
                                 "Bearer OAUTH-SECRET-7391528")
        finally:
            os.environ.pop("AUTH_TEST_ID", None)
            os.environ.pop("AUTH_TEST_SECRET", None)

    async def test_login_request_extracts_json_and_expiry(self):
        def handler(request):
            self.assertEqual(request.url.path, "/login")
            self.assertEqual(json.loads(request.content), {"username": "alice", "password": "PASS-7391528"})
            return httpx.Response(200, json={"access_token": "LOGIN-TOKEN-7391528", "expires_in": 3600})

        os.environ["AUTH_TEST_PASSWORD"] = "PASS-7391528"
        try:
            async with GuardedClient(transport=httpx.MockTransport(handler)) as client:
                manager = AuthManager(_config(_login()), {"owner": "alice"},
                                      "https://target.test", client)
                await manager.initialize()
                self.assertEqual(manager.headers("owner")["Authorization"],
                                 "Bearer LOGIN-TOKEN-7391528")
        finally:
            os.environ.pop("AUTH_TEST_PASSWORD", None)

    async def test_login_request_extracts_header_and_cookie_tokens(self):
        os.environ["AUTH_TEST_PASSWORD"] = "PASS-7391528"
        try:
            for extractor, headers in (
                ("token_header", {"X-Auth-Token": "HEADER-TOKEN-7391528"}),
                ("token_cookie", {"set-cookie": "session=COOKIE-TOKEN-7391528; HttpOnly"}),
            ):
                identity = _login(expiry=False)
                identity["params"].pop("token_json_path")
                identity["params"][extractor] = "X-Auth-Token" if extractor == "token_header" else "session"
                async with GuardedClient(transport=httpx.MockTransport(
                        lambda request: httpx.Response(200, headers=headers))) as client:
                    manager = AuthManager(_config(identity), {"owner": "alice"}, "https://target.test", client)
                    await manager.initialize()
                    expected = "HEADER-TOKEN-7391528" if extractor == "token_header" else "COOKIE-TOKEN-7391528"
                    self.assertEqual(manager.headers("owner")["Authorization"], "Bearer " + expected)
        finally:
            os.environ.pop("AUTH_TEST_PASSWORD", None)

    async def test_script_provider_and_timeout_and_cap(self):
        script = {
            "provider": "script", "environment": "lab",
            "params": {"argv": [sys.executable, "-c",
                                "import json; print(json.dumps({'headers': {'X-Test': 'TOKEN'}, 'expires_in': 60}))"]},
        }
        async with GuardedClient() as client:
            manager = AuthManager(_config(script), {}, "https://target.test", client)
            await manager.initialize()
            self.assertEqual(manager.headers("owner"), {"X-Test": "TOKEN"})
            with self.assertRaises(AuthError) as caught:
                await manager._run_command(
                    {"argv": [sys.executable, "-c", "import time; time.sleep(2)"],
                     "timeout": 0.05, "env": []}, "script")
            self.assertEqual(caught.exception.reason, "script_failed")
            with self.assertRaises(AuthError) as caught:
                await manager._run_command(
                    {"argv": [sys.executable, "-c", "print('x' * 70000)"],
                     "timeout": 5, "env": []}, "script")
            self.assertIn("64 KB", str(caught.exception))

    async def test_login_rejects_wrong_credentials_once_and_caps_attempts(self):
        calls = []

        def handler(request):
            calls.append(request)
            return httpx.Response(401, json={"error": "bad"})

        os.environ["AUTH_TEST_PASSWORD"] = "WRONG-7391528"
        try:
            async with GuardedClient(transport=httpx.MockTransport(handler)) as client:
                manager = AuthManager(_config(_login()), {}, "https://target.test", client)
                with self.assertRaises(AuthError) as caught:
                    await manager.initialize()
                self.assertEqual(caught.exception.reason, "auth_failed")
                self.assertEqual(len(calls), 1)
                self.assertEqual(manager.attempts["owner"], 1)
        finally:
            os.environ.pop("AUTH_TEST_PASSWORD", None)

    async def test_baseline_401_and_403_no_refresh(self):
        tokens = []

        def handler(request):
            if request.url.path == "/login":
                tokens.append(request)
                return httpx.Response(200, json={"access_token": f"T{len(tokens)}", "expires_in": 60})
            return httpx.Response(403)

        os.environ["AUTH_TEST_PASSWORD"] = "PASS-7391528"
        try:
            async with GuardedClient(transport=httpx.MockTransport(handler)) as client:
                manager = AuthManager(_config(_login(refresh=True)), {}, "https://target.test", client)
                await manager.initialize()
                results = await run_rules(_inventory(), [_rule()], client,
                                          contexts=manager.contexts, variables={},
                                          auth_manager=manager)
                self.assertEqual(results[0]["reason"], "baseline_not_2xx")
                self.assertEqual(len(tokens), 1)
        finally:
            os.environ.pop("AUTH_TEST_PASSWORD", None)

    async def test_401_refresh_when_enabled(self):
        calls = {"login": 0, "item": 0}

        def handler(request):
            if request.url.path == "/login":
                calls["login"] += 1
                return httpx.Response(200, json={"access_token": f"T{calls['login']}", "expires_in": 60})
            calls["item"] += 1
            return httpx.Response(401 if calls["item"] == 1 else 200, json={})

        os.environ["AUTH_TEST_PASSWORD"] = "PASS-7391528"
        try:
            async with GuardedClient(transport=httpx.MockTransport(handler)) as client:
                manager = AuthManager(_config(_login(refresh=True)), {}, "https://target.test", client)
                await manager.initialize()
                results = await run_rules(_inventory(), [_rule()], client,
                                          contexts=manager.contexts, variables={},
                                          auth_manager=manager)
                self.assertEqual(calls["login"], 2)
                self.assertEqual(results[0]["status"], "passed")
                self.assertEqual(results[0]["note"], "auth_refreshed")
        finally:
            os.environ.pop("AUTH_TEST_PASSWORD", None)

    async def test_setup_and_teardown_order_and_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hooks.txt"
            command = lambda label: {"argv": [sys.executable, "-c",
                f"from pathlib import Path; Path({str(path)!r}).write_text(Path({str(path)!r}).read_text() + {label!r} if Path({str(path)!r}).exists() else {label!r}); print('{{\"seed\": \"ok\"}}')"],
                "timeout": 5, "env": []}
            config = _config(_login(), setup=command("S"), teardown=command("T"))
            async with GuardedClient() as client:
                manager = AuthManager(config, {}, "https://target.test", client)
                await manager.setup()
                self.assertEqual(manager.variables["seed"], "ok")
                await manager.teardown()
                self.assertEqual(path.read_text(), "ST")
            failing = _config(_login(), setup={"argv": [sys.executable, "-c", "raise SystemExit(4)"],
                                               "timeout": 5, "env": []})
            async with GuardedClient() as client:
                manager = AuthManager(failing, {}, "https://target.test", client)
                with self.assertRaises(AuthError) as caught:
                    await manager.setup()
                self.assertEqual(caught.exception.reason, "setup_failed")

    async def test_file_permissions_and_inline_credential_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret.json"
            path.write_text('{"password": "FILE-SECRET-7391528"}', encoding="utf-8")
            path.chmod(0o644)
            resolver = SecretResolver()
            with self.assertRaises(AuthError) as caught:
                await resolver.resolve(f"file:{path}#password")
            self.assertEqual(caught.exception.reason, "secret_file_permissions")
            path.chmod(0o600)
            self.assertEqual((await resolver.resolve(f"file:{path}#password")).reveal(),
                             "FILE-SECRET-7391528")
        bad = _yaml({"schema_version": "ledgerprobe-auth/1", "identities": {"owner": {
            "provider": "login_request", "environment": "lab",
            "params": {"method": "POST", "path": "/login",
                       "body": {"username": "owner", "password": "INLINE" + "-CREDENTIAL"},
                       "token_json_path": "token"}}}})
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
            yaml.safe_dump(bad, handle)
            name = handle.name
        try:
            with self.assertRaises(AuthError) as caught:
                load_auth_config(name)
            self.assertEqual(caught.exception.reason, "inline_credential")
            self.assertNotIn("INLINE-SECRET", str(caught.exception))
        finally:
            Path(name).unlink(missing_ok=True)

    async def test_vault_and_redactor(self):
        def handler(request):
            self.assertEqual(request.headers["x-vault-token"], "VAULT-TOKEN-7391528")
            return httpx.Response(200, json={"data": {"data": {"password": "VAULT-SECRET-7391528"}}})
        os.environ["VAULT_ADDR"] = "https://vault.test"
        os.environ["VAULT_TOKEN"] = "VAULT-TOKEN-7391528"
        try:
            value = await SecretResolver(transport=httpx.MockTransport(handler)).resolve(
                "vault:secret/data/app#password")
            self.assertEqual(value.reveal(), "VAULT-SECRET-7391528")
        finally:
            os.environ.pop("VAULT_ADDR", None)
            os.environ.pop("VAULT_TOKEN", None)

        secret = Secret("LEAK-SENTINEL-7391528")
        self.assertEqual(repr(secret), "***")
        self.assertEqual(str(secret), "***")
        self.assertEqual(f"{secret}", "***")
        stream = StringIO()
        handler = logging.StreamHandler(stream)
        logging.getLogger().addHandler(handler)
        try:
            logging.getLogger().setLevel(logging.WARNING)
            logging.warning("deliberate leak %s", secret.reveal())
        finally:
            logging.getLogger().removeHandler(handler)
        self.assertNotIn("LEAK-SENTINEL-7391528", stream.getvalue())
        self.assertIn("[REDACTED]", stream.getvalue())
        self.assertEqual(json.dumps({"secret": secret}, default=str), '{"secret": "***"}')
        try:
            raise ValueError(f"token={secret}")
        except ValueError as exc:
            self.assertNotIn("LEAK-SENTINEL-7391528", str(exc))
        self.assertNotIn("LEAK-SENTINEL-7391528", traceback.format_exc())
        self.assertNotIn("LEAK-SENTINEL-7391528", redact(str(secret)))


if __name__ == "__main__":
    unittest.main()
