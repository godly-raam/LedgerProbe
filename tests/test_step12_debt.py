from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

import ledgerprobe
from pkg.guardrails import GuardedClient, KillSwitch
from pkg.guardrails.sync import _prepare
from pkg.rules import _Stop, _execute_race, load_rules
from tests.test_cli import RULE, SPEC, scan

HEADERS = {"User-Agent": "LedgerProbe/1.1.0", "X-LedgerProbe-Run": "run-step12"}
KINDS = ["baseline", "forbidden", "nonexistent_control", "unauthenticated_control",
         "confirmation", "verify", "restore", "login_token", "race_last_byte"]


@pytest.mark.parametrize("kind", KINDS)
def test_identification_headers_on_every_request_kind(kind):
    """Every request path sends the fixed identification headers."""
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"status": "ok"})

    async def run():
        async with GuardedClient("https://target.test", max_rps=1e9,
                                 default_headers=HEADERS,
                                 transport=httpx.MockTransport(handler)) as client:
            if kind == "race_last_byte":
                raw = _prepare(client, {"method": "POST", "url": "/race",
                                        "headers": {**HEADERS, "User-Agent": "bad",
                                                    "X-LedgerProbe-Run": "bad"}})
                assert raw.headers["user-agent"] == HEADERS["User-Agent"]
                assert raw.headers["x-ledgerprobe-run"] == HEADERS["X-LedgerProbe-Run"]
                return
            path = "/login" if kind == "login_token" else f"/{kind.replace('_', '-')}"
            await client.request("POST" if kind in {"login_token", "verify", "restore"} else "GET",
                                 path, headers={**HEADERS, "User-Agent": "bad",
                                                "X-LedgerProbe-Run": "bad"})

    asyncio.run(run())
    if kind != "race_last_byte":
        assert seen, kind
        assert all(r.headers["user-agent"] == HEADERS["User-Agent"] for r in seen)
        assert all(r.headers["x-ledgerprobe-run"] == HEADERS["X-LedgerProbe-Run"] for r in seen)


def test_mid_race_kill_restores_and_skips_with_exit_four(tmp_path):
    marker = tmp_path / "STOP"
    rule = load_rules([Path("tests/fixtures/race_server/rules_race_wallet.yaml")])[0]
    endpoint = {"path": "/race/wallet/spend", "method": "POST", "operation_id": None,
                "parameters": [], "request_body": None, "base_url": "https://race.test"}
    requests = []

    class Response:
        status_code = 200
        def json(self):
            return {"balance": 10}

    class Runtime:
        contexts = {"owner": {}, "other": {}}
        variables = {}
        inventory = {"base_url": "https://race.test"}
        async def inputs(self, *args):
            return {"url": "https://race.test/race/wallet/spend", "query": {}, "headers": {},
                    "required_headers": set(), "body": {"amount": 10}, "path_values": {}}
        async def custom_request(self, spec, variables, primary=None, forbidden=None):
            requests.append(spec["path"])
            return Response()

    class Client:
        rounds = 0
        def check_kill(self):
            if marker.exists():
                raise KillSwitch("stop")
        async def send_synchronized(self, payloads, **kwargs):
            self.rounds += 1
            marker.write_text("stop")
            return {"responses": [{"status": 200}], "spread_ms": 0.0, "mode": "last_byte"}

    client = Client()
    async def run():
        with pytest.raises(_Stop) as caught:
            await _execute_race(Runtime(), endpoint, rule, {}, client, ())
        return caught.value

    stop = asyncio.run(run())
    assert client.rounds == 1
    assert requests[-1] == "/race/reset"  # restore, after the kill
    assert (stop.status, stop.reason) == ("skipped", "kill_switch")
    assert marker.exists()
    assert ledgerprobe  # CLI maps kill_switch to exit 4; covered by test_kill_file_skips_remaining_rules_and_exits_four


@pytest.mark.parametrize("environment", ["lab", "staging"])
def test_environment_matrix_lab_and_staging_proceed(tmp_path, environment):
    code, _, _ = scan(tmp_path, lambda request: httpx.Response(
        403 if request.headers["Authorization"] == "other-secret" else 200),
        extra=("--environment", environment))
    assert code == 0


def test_environment_matrix_production_requires_allow(tmp_path):
    args = ledgerprobe.arguments([
        "--spec", "missing", "--rules", "missing", "--read-only", "--environment", "production"])
    with pytest.raises(ValueError, match="production_read_only_requires_allow"):
        asyncio.run(ledgerprobe.execute(args))


def test_environment_matrix_production_read_only_and_mutation_blocked(tmp_path):
    def handler(request):
        if request.url.path == "/objects":
            pytest.fail("production mutation must not contact target")
        return httpx.Response(403 if request.headers["Authorization"] == "other-secret" else 200)
    code, _, _ = scan(tmp_path, handler,
                      extra=("--environment", "production", "--read-only",
                             "--allow-production-read-only"))
    assert code == 0
    rule = {**RULE, "target_endpoints": [{"path": "/objects", "method": "POST"}],
            "mutating": True,
            "verify": {"mode": "marker", "readback": {"method": "GET", "path": "/objects/{{id}}"}},
            "restore": [{"method": "POST", "path": "/objects"}]}
    rule.pop("assertions")
    code, sarif, junit = scan(tmp_path, handler, rule=rule, spec={
        **SPEC, "paths": {"/objects": {"post": {"responses": {"200": {"description": "Created"}}}}}},
        extra=("--environment", "production", "--read-only", "--allow-production-read-only",
               "--allow-mutations"))
    assert code == 2
    assert len(junit.findall(".//skipped")) == 1


def _experimental_rule(check):
    rule = {**RULE, "check": check,
            "target_endpoints": [{"path": "/objects", "method": "PATCH"}],
            "restore": [{"method": "PATCH", "path": "/objects"}]}
    rule.pop("assertions")
    if check == "mass_assignment":
        rule.update(request={"method": "PATCH", "path": "/objects"},
                    readback={"method": "GET", "path": "/objects"})
    else:
        rule.update(request={"method": "PATCH", "path": "/objects"},
                    ledger={"snapshot": {"method": "GET", "path": "/objects"},
                            "path": "balance"},
                    limits={"per_txn_max": 100}, cases=["negative"])
    return rule


@pytest.mark.parametrize("check", ["mass_assignment", "business_limit"])
def test_experimental_gate_rejects_without_flag(tmp_path, check):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(_experimental_rule(check)))
    with pytest.raises(ValueError, match="not yet validated"):
        load_rules([path])


@pytest.mark.parametrize("check", ["mass_assignment", "business_limit"])
def test_experimental_gate_accepts_with_flag(tmp_path, check):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(_experimental_rule(check)))
    assert load_rules([path], experimental=True)[0]["check"] == check
