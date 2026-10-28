from __future__ import annotations

import json
import time
from dataclasses import dataclass

import httpx

MAX_BODY_CHARS = 1500


@dataclass(frozen=True)
class Session:
    token: str
    user: dict

    @property
    def id(self) -> str:
        return self.user["id"]


def _body_text(payload) -> str:
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    text = json.dumps(payload, separators=(",", ":"))
    return text if len(text) <= MAX_BODY_CHARS else text[:MAX_BODY_CHARS] + "...[truncated]"


class BankAPI:
    def __init__(self, base_url: str, timeout: float = 15.0, concurrency: int = 40):
        self.base_url = base_url.rstrip("/")
        self._http = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            limits=httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency),
        )

    async def close(self) -> None:
        await self._http.aclose()

    async def call(
        self,
        method: str,
        path: str,
        token: str | None = None,
        payload: dict | list | None = None,
    ) -> dict:
        headers = {"content-type": "application/json"}
        if token:
            headers["authorization"] = f"Bearer {token}"
        started = time.perf_counter()
        response = await self._http.request(method, path, headers=headers, json=payload)
        duration_ms = round((time.perf_counter() - started) * 1000, 2)

        try:
            parsed = response.json()
        except ValueError:
            parsed = response.text

        return {
            "request": {
                "method": method,
                "path": path,
                "headers": {
                    "content-type": "application/json",
                    "authorization": "Bearer <redacted>" if token else "<none>",
                },
                "body": payload,
            },
            "response": {"status": response.status_code, "body": parsed},
            "duration_ms": duration_ms,
        }

    async def login(self, email: str, password: str = "demo1234") -> Session:
        result = await self.call("POST", "/api/v1/auth/login", payload={"email": email, "password": password})
        if result["response"]["status"] != 200:
            raise RuntimeError(f"login failed for {email}: {result['response']}")
        return Session(result["response"]["body"]["access_token"], result["response"]["body"]["user"])

    async def reset(self) -> None:
        result = await self.call("POST", "/api/v1/dev/reset")
        status = result["response"]["status"]
        if status != 200:
            raise RuntimeError(
                "lab reset failed "
                f"({status}: {result['response']['body']}). "
                "Set ALLOW_RESET=true in mock-bank-api/config.json."
            )
