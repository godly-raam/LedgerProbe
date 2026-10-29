"""Async HTTP safety gates, without redirects or automatic retries."""

from __future__ import annotations

import asyncio
import math
from collections import deque
from email.utils import parsedate_to_datetime
from time import monotonic, time

import httpx

__all__ = ["GuardedClient", "TokenBucket", "UnsafeRequest"]


class UnsafeRequest(ValueError):
    """A request would violate the client's safety policy."""


def _positive(value, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be finite and positive")
    try:
        result = float(value)
    except OverflowError:
        raise ValueError(f"{name} must be finite and positive") from None
    if not math.isfinite(result) or result <= 0:
        raise ValueError(f"{name} must be finite and positive")
    return result


class TokenBucket:
    """A cancellation-safe async token bucket (tokens/second).

    Starts full. The default capacity of one avoids startup bursts. Each
    ``acquire()`` consumes one token; cancelled waiters reserve no tokens.
    """

    def __init__(self, rate: float, capacity: float = 1.0):
        self.rate = _positive(rate, "rate")
        self.capacity = _positive(capacity, "capacity")
        if self.capacity < 1:
            raise ValueError("capacity must be at least one token")
        self._tokens = self.capacity
        self._updated = monotonic()
        self._condition = asyncio.Condition()

    def _delay(self, now: float) -> float:
        self._tokens = min(
            self.capacity, self._tokens + (now - self._updated) * self.rate
        )
        self._updated = now
        return max(0.0, (1.0 - self._tokens) / self.rate)

    async def acquire(self) -> None:
        async with self._condition:
            while True:
                delay = self._delay(monotonic())
                if delay == 0:
                    self._tokens -= 1
                    return
                await _wait(self._condition, delay)


async def _wait(condition: asyncio.Condition, delay: float) -> None:
    try:
        await asyncio.wait_for(condition.wait(), timeout=delay)
    except asyncio.TimeoutError:
        pass


class GuardedClient:
    """An httpx-compatible request facade with shared admission control.

    ``concurrency`` is the configured ceiling; ``current_limit`` is the
    read-only adaptive limit. A 429 halves it immediately. A window of up to
    20 responses with at least five samples and >=50% 5xx also halves it.
    Twenty consecutive non-error responses recover one slot at a time.

    Read-only exceptions match the uppercase method and exact resolved,
    URL-encoded path (excluding query). Redirects cannot be enabled. No
    response is retried, including mutations. Retry-After on 429/5xx imposes
    a global cooldown capped at 60 seconds; 429 defaults to one second.
    Already-running requests are not cancelled when the limit falls.
    """

    def __init__(
        self,
        base_url='',
        max_rps=10.0,
        concurrency=4,
        read_only=False,
        allow_mutations=(),
        timeout=15.0,
        transport=None,
    ):
        rate = _positive(max_rps, "max_rps")
        _positive(concurrency, "concurrency")
        if not isinstance(concurrency, int) or isinstance(concurrency, bool):
            raise ValueError("concurrency must be a positive integer")
        timeout = _positive(timeout, "timeout")
        allowed = set()
        for entry in allow_mutations:
            if (
                not isinstance(entry, tuple)
                or len(entry) != 2
                or not all(isinstance(part, str) for part in entry)
            ):
                raise ValueError("allow_mutations must contain (METHOD, path) tuples")
            allowed.add(entry)
        self._allowed = frozenset(allowed)
        self._read_only = read_only
        self._concurrency = concurrency
        self._current_limit = concurrency
        self._active = 0
        self._condition = asyncio.Condition()
        self._bucket = TokenBucket(rate)
        self._cooldown_until = 0.0
        self._window = deque(maxlen=20)
        self._successes = 0
        self._closed = False
        self._http = httpx.AsyncClient(
            base_url=base_url, timeout=timeout, transport=transport,
            follow_redirects=False,
        )

    @property
    def concurrency(self) -> int:
        return self._concurrency

    @property
    def current_limit(self) -> int:
        return self._current_limit

    async def __aenter__(self):
        await self._http.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.aclose()

    async def aclose(self) -> None:
        async with self._condition:
            self._closed = True
            self._condition.notify_all()
        await self._http.aclose()

    async def _acquire(self) -> None:
        async with self._condition:
            while True:
                if self._closed:
                    raise RuntimeError("GuardedClient is closed")
                now = monotonic()
                delay = max(self._bucket._delay(now), self._cooldown_until - now)
                if self._active < self._current_limit and delay <= 0:
                    self._bucket._tokens -= 1
                    self._active += 1
                    return
                if self._active >= self._current_limit:
                    await self._condition.wait()
                else:
                    await _wait(self._condition, delay)

    def _feedback(self, response: httpx.Response) -> None:
        status = response.status_code
        server_error = 500 <= status < 600
        self._window.append(server_error)
        overloaded = status == 429 or (
            len(self._window) >= 5 and sum(self._window) / len(self._window) >= 0.5
        )
        if overloaded:
            self._current_limit = max(1, self._current_limit // 2)
            self._window.clear()
        if overloaded or server_error or status >= 400:
            self._successes = 0
        else:
            self._successes += 1
            if self._successes >= 20:
                self._current_limit = min(self.concurrency, self._current_limit + 1)
                self._successes = 0

        if status == 429 or server_error:
            delay = self._retry_after(response.headers.get("Retry-After"))
            if delay is None:
                delay = 1.0 if status == 429 else 0.0
            self._cooldown_until = max(self._cooldown_until, monotonic() + delay)

    @staticmethod
    def _retry_after(value: str | None) -> float | None:
        if value is None:
            return None
        try:
            delay = float(value)
        except ValueError:
            try:
                date = parsedate_to_datetime(value)
                if date.tzinfo is None:
                    return None
                delay = date.timestamp() - time()
            except (ValueError, TypeError, OverflowError):
                return None
        if not math.isfinite(delay):
            return None
        return min(60.0, max(0.0, delay))

    async def request(self, method: str, url, **kwargs) -> httpx.Response:
        follow = kwargs.pop("follow_redirects", False)
        if follow not in (False, httpx.USE_CLIENT_DEFAULT):
            raise UnsafeRequest("redirects cannot be enabled")
        auth = kwargs.pop("auth", httpx.USE_CLIENT_DEFAULT)
        request = self._http.build_request(method, url, **kwargs)
        path = request.url.raw_path.split(b"?", 1)[0].decode("ascii")
        if (
            self._read_only
            and request.method not in {"GET", "HEAD", "OPTIONS"}
            and (request.method, path) not in self._allowed
        ):
            raise UnsafeRequest(f"read-only policy blocks {request.method} {path}")
        await self._acquire()
        response = None
        try:
            response = await self._http.send(request, auth=auth, follow_redirects=False)
            return response
        finally:
            async with self._condition:
                self._active -= 1
                if response is not None:
                    self._feedback(response)
                self._condition.notify_all()

    async def get(self, url, **kwargs) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def head(self, url, **kwargs) -> httpx.Response:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url, **kwargs) -> httpx.Response:
        return await self.request("OPTIONS", url, **kwargs)

    async def post(self, url, **kwargs) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def put(self, url, **kwargs) -> httpx.Response:
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url, **kwargs) -> httpx.Response:
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url, **kwargs) -> httpx.Response:
        return await self.request("DELETE", url, **kwargs)
