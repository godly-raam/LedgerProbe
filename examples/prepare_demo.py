"""Prepare the quick-start spec and auth references; never used by the engine."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import tempfile
from pathlib import Path

import yaml

from pkg.guardrails import GuardedClient

AUTH_FILENAME = "ledgerprobe-auth.yaml"
DEFAULT_PASSWORD_ENV = "LEDGERPROBE_DEMO_PASSWORD"
DEMO_IDENTITIES = {
    "parent_user_a": "parent.a@finshield.dev",
    "parent_user_b": "parent.b@finshield.dev",
}


def auth_document(password_env: str = DEFAULT_PASSWORD_ENV) -> dict:
    """Return a login-request config that resolves passwords at scan time."""
    identities = {}
    for name, email in DEMO_IDENTITIES.items():
        identities[name] = {
            "provider": "login_request",
            "environment": "lab",
            "params": {
                "method": "POST",
                "path": "/api/v1/auth/login",
                "body": {
                    "email": email,
                    "password_ref": f"env:{password_env}",
                },
                "token_json_path": "access_token",
                "expiry_json_path": "expires_in",
                "header_format": "Bearer {token}",
            },
        }
    return {"schema_version": "ledgerprobe-auth/1", "identities": identities}


def _write_private(path: Path, text: str) -> None:
    """Atomically write a demo artifact with owner-only permissions."""
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(text)
            stream.close()
            os.replace(temporary, path)
            path.chmod(0o600)
        finally:
            temporary.unlink(missing_ok=True)


async def prepare(base_url: str, out: Path, password_env: str = DEFAULT_PASSWORD_ENV) -> None:
    out.mkdir(parents=True, exist_ok=True)
    async with GuardedClient(base_url=base_url, max_rps=5) as client:
        response = await client.get("/openapi.json")
        response.raise_for_status()
        spec = response.json()

    (out / "openapi.json").write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    _write_private(
        out / "inputs.json",
        json.dumps({"variables": {"teen_id": "usr_teen_a"}}) + "\n",
    )
    _write_private(
        out / AUTH_FILENAME,
        yaml.safe_dump(auth_document(password_env), sort_keys=False),
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--out", type=Path, default=Path(".demo"))
    parser.add_argument(
        "--password-env",
        default=DEFAULT_PASSWORD_ENV,
        help="environment variable containing the fixture password reference",
    )
    args = parser.parse_args()
    asyncio.run(prepare(args.base_url, args.out, args.password_env))
