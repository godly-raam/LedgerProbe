import asyncio
import json

import pytest

import ledgerprobe
from tests.test_cli import RULE, SPEC, scan


def mutating_rule():
    rule = {**RULE, "target_endpoints": [{"path": "/objects", "method": "POST"}],
            "mutating": True,
            "verify": {"mode": "marker", "readback": {"method": "GET", "path": "/objects/{{id}}"}},
            "restore": [{"method": "POST", "path": "/objects"}]}
    rule.pop("assertions")
    return rule


def spec():
    return {**SPEC, "paths": {"/objects": {"post": {"responses": {"200": {"description": "Created"}}}}}}


def test_production_hard_blocks_mutation_without_http(tmp_path):
    def no_http(request):
        pytest.fail("production mutation must not contact target")
    code, _, junit = scan(tmp_path, no_http, rule=mutating_rule(), spec=spec(),
                          extra=("--allow-mutations", "--environment", "production"))
    assert code == 2
    assert len(junit.findall(".//skipped")) == 1


def test_production_read_only_requires_explicit_allow(tmp_path):
    args = ledgerprobe.arguments([
        "--spec", "missing", "--rules", "missing", "--read-only", "--environment", "production"])
    with pytest.raises(ValueError, match="production_read_only_requires_allow"):
        asyncio.run(ledgerprobe.execute(args))


def test_identity_environment_mismatch_is_terminal(tmp_path):
    auth = tmp_path / "auth.yaml"
    auth.write_text(json.dumps({
        "schema_version": "ledgerprobe-auth/1",
        "identities": {"owner": {"provider": "static_header", "environment": "staging",
                                 "params": {"header": "Authorization", "value_ref": "env:OWNER"}}},
    }))
    rules = tmp_path / "r.json"
    rules.write_text(json.dumps(RULE))
    args = ledgerprobe.arguments([
        "--spec", "missing", "--rules", str(rules), "--auth", str(auth),
        "--environment", "lab"])
    assert asyncio.run(ledgerprobe.execute(args)) == 2


def test_kill_file_skips_remaining_rules_and_exits_four(tmp_path):
    marker = tmp_path / "STOP"
    marker.write_text("stop")
    def no_http(request):
        pytest.fail("killed scan must not contact target")
    code, _, junit = scan(tmp_path, no_http, extra=("--kill-file", str(marker)))
    assert code == 4
    assert len(junit.findall(".//skipped")) == 1
