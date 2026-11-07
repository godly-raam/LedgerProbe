"""End-to-end quick-start scan using environment-backed login credentials."""

from __future__ import annotations

import asyncio
import json
import re
import secrets
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

import ledgerprobe
from examples import prepare_demo
from pkg.guardrails import GuardedClient

TOKEN_SHAPE = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_-])"
)


def test_quickstart_uses_auth_and_writes_no_token(tmp_path, monkeypatch, capsys):
    pytest.importorskip("fastapi")
    pytest.importorskip("sqlalchemy")
    pytest.importorskip("jwt")

    sentinel = "quickstart-sentinel-" + secrets.token_urlsafe(24)
    monkeypatch.setenv("MOCK_BANK_PASSWORD", sentinel)
    monkeypatch.setenv("LEDGERPROBE_DEMO_PASSWORD", sentinel)
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "mock-bank-api"))

    from app.config import Settings
    from app.main import create_app

    app = create_app(Settings(database_url="sqlite://", enable_bola_bug=True))
    transport = httpx.ASGITransport(app=app)
    out = tmp_path / "quickstart"
    args = ledgerprobe.arguments([
        "--spec", str(out / "openapi.json"), "--base-url", "http://lab.test",
        "--rules", "rulesets/abac_isolation.yaml",
        "--auth", str(out / prepare_demo.AUTH_FILENAME),
        "--inputs", str(out / "inputs.json"),
        "--read-only", "--max-rps", "5",
        "--sarif", str(out / "results.sarif"),
        "--junit", str(out / "results.xml"),
    ])

    def client(**kwargs):
        kwargs["max_rps"] = 10000
        return GuardedClient(transport=transport, **kwargs)

    async def execute():
        async with app.router.lifespan_context(app):
            with patch.object(prepare_demo, "GuardedClient", side_effect=client):
                await prepare_demo.prepare("http://lab.test", out)
            async with httpx.AsyncClient(transport=transport, base_url="http://lab.test") as http:
                response = await http.post(
                    "/api/v1/auth/login",
                    json={"email": "parent.a@finshield.dev", "password": sentinel},
                )
                response.raise_for_status()
                token = response.json()["access_token"]
            with patch.object(ledgerprobe, "GuardedClient", side_effect=client):
                code = await ledgerprobe.execute(args)
        return code, token

    code, token = asyncio.run(execute())
    captured = capsys.readouterr()
    output = captured.out + captured.err

    assert code == 1
    assert (out / "results.sarif").is_file()
    assert "[failed] bola-cross-tenant-access" in output
    assert "legacy_static_credentials" not in output
    assert json.loads((out / "inputs.json").read_text()) == {"variables": {"teen_id": "usr_teen_a"}}
    auth = (out / prepare_demo.AUTH_FILENAME).read_text()
    assert "provider: login_request" in auth
    assert "password_ref: env:LEDGERPROBE_DEMO_PASSWORD" in auth
    assert sentinel not in auth

    for path in out.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert token not in text, path
        assert sentinel not in text, path
        assert not TOKEN_SHAPE.search(text), path
