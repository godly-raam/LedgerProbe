"""Scan the unchanged mock bank in-process with both configurations; no network."""
import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

import ledgerprobe
from examples import prepare_demo
from pkg.guardrails import GuardedClient


@pytest.mark.parametrize("enabled,expected_exit,expected_verdict", [(True, 1, "FAIL"), (False, 0, "PASS")])
def test_lab_bola_on_and_off(tmp_path, monkeypatch, enabled, expected_exit, expected_verdict):
    pytest.importorskip("fastapi")
    pytest.importorskip("sqlalchemy")
    pytest.importorskip("jwt")
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "mock-bank-api"))
    from app.config import Settings
    from app.main import create_app

    # Exercise the real ENABLE_BOLA_BUG config key without changing lab files.
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"DATABASE_URL": "sqlite://", "ENABLE_BOLA_BUG": enabled}))
    app = create_app(Settings.load(config))
    transport = httpx.ASGITransport(app=app)
    def client(**kwargs):
        kwargs["max_rps"] = 10000
        return GuardedClient(transport=transport, **kwargs)
    args = ledgerprobe.arguments([
        "--spec", str(tmp_path / "openapi.json"), "--base-url", "http://lab.test",
        "--rules", "rulesets/abac_isolation.yaml", "--inputs", str(tmp_path / "inputs.json"),
        "--read-only", "--sarif", str(tmp_path / "results.sarif"), "--junit", str(tmp_path / "results.xml"),
    ])
    observed = []
    original = ledgerprobe.run_rules
    async def recording(*args, **kwargs):
        results = await original(*args, **kwargs)
        observed.extend(results)
        return results
    async def execute():
        async with app.router.lifespan_context(app):
            with patch.object(prepare_demo, "GuardedClient", side_effect=client):
                await prepare_demo.prepare("http://lab.test", tmp_path)
            assert (tmp_path / "inputs.json").stat().st_mode & 0o777 == 0o600
            with patch.object(ledgerprobe, "GuardedClient", side_effect=client), \
                 patch.object(ledgerprobe, "run_rules", side_effect=recording):
                return await ledgerprobe.execute(args)
    assert asyncio.run(execute()) == expected_exit
    assert len(observed) == 1
    assert observed[0]["verdict"] == expected_verdict
    if enabled:
        assert observed[0]["reason"] == "leak_detected"
        assert observed[0]["evidence"]["confirm_runs"] == 2
    reports = (tmp_path / "results.sarif").read_text() + (tmp_path / "results.xml").read_text()
    assert "usr_teen_a" not in reports
    for headers in json.loads((tmp_path / "inputs.json").read_text())["contexts"].values():
        for credential in headers.values():
            assert credential not in reports
