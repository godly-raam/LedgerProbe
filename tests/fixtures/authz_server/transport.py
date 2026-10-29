from __future__ import annotations

import asyncio
import httpx


class TimingOutASGITransport(httpx.ASGITransport):
    """An ASGITransport that enforces HTTPX read timeouts deterministically."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        timeout_config = request.extensions.get("timeout", {})
        timeout = timeout_config.get("read")
        if timeout is not None and timeout > 0:
            try:
                return await asyncio.wait_for(super().handle_async_request(request), timeout=timeout)
            except asyncio.TimeoutError:
                raise httpx.ReadTimeout("The read operation timed out", request=request)
        return await super().handle_async_request(request)
