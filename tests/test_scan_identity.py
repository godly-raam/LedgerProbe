import asyncio

import httpx
import pytest

from pkg.guardrails import GuardedClient
from pkg.guardrails.sync import _prepare


def test_identification_headers_are_forced_on_normal_and_raw_requests():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200)

    async def scenario():
        headers = {"User-Agent": "LedgerProbe/1.1.0", "X-LedgerProbe-Run": "pipeline-42"}
        async with GuardedClient("https://target.test", max_rps=1e9,
                                 default_headers=headers,
                                 transport=httpx.MockTransport(handler)) as client:
            # A rule cannot replace the identification headers.
            await client.get("/objects/1", headers={**headers, "User-Agent": "custom",
                                                    "X-LedgerProbe-Run": "other"})
            raw = _prepare(client, {"method": "POST", "url": "/race",
                                    "headers": {**headers, "X-LedgerProbe-Run": "other"}})
            assert raw.headers["user-agent"] == "LedgerProbe/1.1.0"
            assert raw.headers["x-ledgerprobe-run"] == "pipeline-42"

    asyncio.run(scenario())
    assert seen[0].headers["user-agent"] == "LedgerProbe/1.1.0"
    assert seen[0].headers["x-ledgerprobe-run"] == "pipeline-42"
