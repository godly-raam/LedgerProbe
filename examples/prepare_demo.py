"""Prepare synthetic lab credentials and a local spec; never used by the engine."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import tempfile
from pathlib import Path

from pkg.guardrails import GuardedClient


async def prepare(base_url: str, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    async with GuardedClient(base_url=base_url, max_rps=5) as client:
        response = await client.get("/openapi.json")
        response.raise_for_status()
        spec = response.json()
        contexts = {}
        for name, email in [("parent_user_a", "parent.a@finshield.dev"), ("parent_user_b", "parent.b@finshield.dev")]:
            response = await client.post("/api/v1/auth/login", json={"email": email, "password": "demo1234"})
            response.raise_for_status()
            contexts[name] = {"Authorization": "Bearer " + response.json()["access_token"]}
    (out / "openapi.json").write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    # Atomic replacement preserves mode 0600 even if an earlier file was public.
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=out, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump({"contexts": contexts, "variables": {"teen_id": "usr_teen_a"}}, stream)
            stream.write("\n")
            stream.close()
            os.replace(temporary, out / "inputs.json")
        finally:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--out", type=Path, default=Path(".demo"))
    args = parser.parse_args()
    asyncio.run(prepare(args.base_url, args.out))
