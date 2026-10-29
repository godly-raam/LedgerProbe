import asyncio
from datetime import datetime, timezone
from email.utils import format_datetime
from unittest.mock import patch

import httpx
import pytest

import pkg.guardrails as guardrails
from pkg.guardrails import GuardedClient, TokenBucket, UnsafeRequest


def run(coro):
    return asyncio.run(coro)


async def settle():
    # Let condition waiters and wait_for's child tasks reach their next await.
    for _ in range(10):
        await asyncio.sleep(0)


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    async def advance(self, seconds, condition):
        self.now += seconds
        async with condition:
            condition.notify_all()
        await settle()


@pytest.mark.parametrize("name", ["max_rps", "concurrency", "timeout"])
@pytest.mark.parametrize("value", [0, -1, float("nan"), float("inf"), -float("inf"), True, "2", None])
def test_invalid_config(name, value):
    with pytest.raises(ValueError):
        GuardedClient(**{name: value})


@pytest.mark.parametrize("value", [0.5, 2.0])
def test_concurrency_requires_integer(value):
    with pytest.raises(ValueError):
        GuardedClient(concurrency=value)


@pytest.mark.parametrize("kwargs", [{"rate": 0}, {"rate": float("nan")}, {"rate": 1, "capacity": 0.5}, {"rate": 1, "capacity": float("inf")}])
def test_bucket_validation(kwargs):
    with pytest.raises(ValueError):
        TokenBucket(**kwargs)


def test_bucket_refill_capacity_and_cancelled_waiter():
    async def scenario():
        clock = Clock()
        with patch.object(guardrails, "monotonic", clock):
            bucket = TokenBucket(2, capacity=2)
            await bucket.acquire()
            await bucket.acquire()
            cancelled = asyncio.create_task(bucket.acquire())
            await settle()
            assert not cancelled.done()
            cancelled.cancel()
            with pytest.raises(asyncio.CancelledError):
                await cancelled
            waiter = asyncio.create_task(bucket.acquire())
            await clock.advance(0.25, bucket._condition)
            assert not waiter.done()
            await clock.advance(0.25, bucket._condition)
            await waiter
            assert bucket._tokens == 0
            await clock.advance(100, bucket._condition)
            await bucket.acquire()
            assert bucket._tokens == 1
    run(scenario())


def test_httpx_parameters_verbs_and_context_close():
    async def scenario():
        seen = []

        async def handler(request):
            seen.append(request)
            return httpx.Response(200, json={"ok": True})

        async with GuardedClient(
            "https://bank.test/api/", max_rps=1e9,
            transport=httpx.MockTransport(handler),
        ) as client:
            response = await client.post(
                "pay", params={"q": "a b"}, json={"amount": 12},
                headers={"X-Test": "yes"}, cookies={"session": "abc"},
                auth=("user", "pass"), timeout=2,
            )
            assert isinstance(response, httpx.Response)
            assert response.json() == {"ok": True}
            request = seen[0]
            assert str(request.url) == "https://bank.test/api/pay?q=a+b"
            assert request.content == b'{"amount":12}'
            assert request.headers["x-test"] == "yes"
            assert request.headers["cookie"] == "session=abc"
            assert request.headers["authorization"].startswith("Basic ")
            assert request.extensions["timeout"]["read"] == 2
            for method in ("get", "head", "options", "put", "patch", "delete"):
                await getattr(client, method)("/other")
            await client.request("CUSTOM", "/custom")
            assert [r.method for r in seen] == [
                "POST", "GET", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE", "CUSTOM"
            ]
        assert client._http.is_closed
        with pytest.raises(RuntimeError):
            await client.get("/")
        await client.aclose()
    run(scenario())


def test_read_only_exact_resolved_paths_and_no_redirects():
    async def scenario():
        seen = []

        def handler(request):
            seen.append(request)
            return httpx.Response(307, headers={"location": "https://other.test/pay"})

        async with GuardedClient(
            "https://bank.test/api/", max_rps=1e9, read_only=True,
            allow_mutations=(("POST", "/api/pay"),),
            transport=httpx.MockTransport(handler),
        ) as client:
            for method in ("GET", "HEAD", "OPTIONS"):
                response = await client.request(method, "pay", follow_redirects=False)
                assert response.status_code == 307
                assert not response.history
            await client.post("pay", params={"id": 1})
            await client.request("post", "https://bank.test/api/pay?x=1")
            for method, url in [
                ("POST", "https://bank.test/pay"), ("PUT", "pay"),
                ("POST", "pay/child"), ("POST", "pay/"),
                ("POST", "https://bank.test/api/%70ay"), ("CUSTOM", "pay"),
            ]:
                with pytest.raises(UnsafeRequest):
                    await client.request(method, url)
            with pytest.raises(UnsafeRequest):
                await client.get("pay", follow_redirects=True)
            assert len(seen) == 5
    run(scenario())


def test_all_verbs_and_absolute_urls_share_rate_gate():
    async def scenario():
        clock = Clock()
        sent = []
        with patch.object(guardrails, "monotonic", clock):
            async with GuardedClient(
                "https://bank.test", max_rps=2,
                transport=httpx.MockTransport(lambda r: (sent.append(r), httpx.Response(200))[1]),
            ) as client:
                await client.get("/first")
                tasks = [asyncio.create_task(client.request(method, url)) for method, url in [
                    ("POST", "https://other.test/pay"), ("PATCH", "/patch"),
                    ("DELETE", "/delete"), ("PUT", "/put"),
                    ("HEAD", "/head"), ("OPTIONS", "/options"),
                ]]
                await settle()
                assert len(sent) == 1
                for count in range(2, 8):
                    await clock.advance(0.5, client._condition)
                    assert len(sent) == count
                await asyncio.gather(*tasks)
    run(scenario())


def test_429_reduces_live_limit_and_cooldown_rechecks_existing_waiters():
    async def scenario():
        clock = Clock()
        release_overload = asyncio.Event()
        release_active = asyncio.Event()
        sent = []

        async def handler(request):
            sent.append(request.url.path)
            if request.url.path == "/overload":
                await release_overload.wait()
                return httpx.Response(429, headers={"Retry-After": "2"})
            if request.url.path == "/active":
                await release_active.wait()
            return httpx.Response(200)

        with patch.object(guardrails, "monotonic", clock):
            async with GuardedClient(
                "https://bank.test", max_rps=10, concurrency=2,
                transport=httpx.MockTransport(handler),
            ) as client:
                first = asyncio.create_task(client.post("/overload"))
                await settle()
                active = asyncio.create_task(client.get("/active"))
                await clock.advance(0.125, client._condition)
                assert len(sent) == 2
                queued = asyncio.create_task(client.get("https://other.test/queued"))
                second = asyncio.create_task(client.get("/second"))
                await settle()
                release_overload.set()
                assert (await first).status_code == 429
                assert client.current_limit == 1
                assert client.concurrency == 2
                release_active.set()
                await active
                await clock.advance(1, client._condition)
                assert len(sent) == 2
                await clock.advance(1, client._condition)
                assert len(sent) == 3
                # Cooldown expiration grants no burst and no rate bypass.
                await clock.advance(0.125, client._condition)
                await asyncio.gather(queued, second)
                assert len(sent) == 4
    run(scenario())


def test_cooldown_interrupts_existing_rate_waiters():
    async def scenario():
        clock = Clock()
        release = asyncio.Event()
        sent = []

        async def handler(request):
            sent.append(request.url.path)
            if request.url.path == "/overload":
                await release.wait()
                return httpx.Response(429, headers={"Retry-After": "2"})
            return httpx.Response(200)

        with patch.object(guardrails, "monotonic", clock):
            async with GuardedClient(
                "https://bank.test", max_rps=2, concurrency=4,
                transport=httpx.MockTransport(handler),
            ) as client:
                active = asyncio.create_task(client.get("/overload"))
                await settle()
                waiter = asyncio.create_task(client.get("/waiting"))
                await settle()
                assert sent == ["/overload"]
                release.set()
                await active
                await clock.advance(0.5, client._condition)
                assert not waiter.done()
                await clock.advance(1.5, client._condition)
                await waiter
                assert sent == ["/overload", "/waiting"]
    run(scenario())


def test_concurrency_ceiling_is_enforced_at_transport():
    async def scenario():
        releases = asyncio.Queue()
        active = 0
        peak = 0
        started = 0

        async def handler(request):
            nonlocal active, peak, started
            active += 1
            started += 1
            peak = max(peak, active)
            try:
                await releases.get()
                return httpx.Response(200)
            finally:
                active -= 1

        async with GuardedClient(
            "https://bank.test", max_rps=1e9, concurrency=2,
            transport=httpx.MockTransport(handler),
        ) as client:
            tasks = [asyncio.create_task(client.get("/")) for _ in range(6)]
            await settle()
            assert started == 2
            for expected in range(3, 7):
                releases.put_nowait(None)
                await settle()
                assert started == expected
                assert active == 2
            releases.put_nowait(None)
            releases.put_nowait(None)
            await asyncio.gather(*tasks)
            assert peak == 2
    run(scenario())


def test_5xx_window_recovery_and_mutations_never_retry():
    async def scenario():
        statuses = iter([500, 200, 503, 200, 502] + [200] * 40)
        sent = []

        def handler(request):
            sent.append(request)
            return httpx.Response(next(statuses))

        async with GuardedClient(
            "https://bank.test", max_rps=1e9, concurrency=4,
            transport=httpx.MockTransport(handler),
        ) as client:
            for _ in range(4):
                await client.post("/pay")
            assert client.current_limit == 4
            await client.post("/pay")
            assert client.current_limit == 2
            for _ in range(19):
                await client.get("/")
            assert client.current_limit == 2
            await client.get("/")
            assert client.current_limit == 3
            for _ in range(20):
                await client.get("/")
            assert client.current_limit == 4
            assert len(sent) == 45
    run(scenario())


def test_retry_after_dates_invalid_values_and_cap():
    with patch.object(guardrails, "time", return_value=1000):
        date = format_datetime(datetime.fromtimestamp(1010, timezone.utc), usegmt=True)
        assert GuardedClient._retry_after(date) == 10
        assert GuardedClient._retry_after("9999999") == 60
        assert GuardedClient._retry_after("-1") == 0
        assert GuardedClient._retry_after("0.25") == 0.25
        for value in (None, "garbage", "nan", "inf"):
            assert GuardedClient._retry_after(value) is None


def test_default_cooldown_and_503_retry_after_cannot_shorten_existing_cooldown():
    async def scenario():
        clock = Clock()
        with patch.object(guardrails, "monotonic", clock):
            async with GuardedClient(transport=httpx.MockTransport(lambda r: httpx.Response(200))) as client:
                client._feedback(httpx.Response(429, headers={"Retry-After": "invalid"}))
                assert client._cooldown_until == 1001
                client._feedback(httpx.Response(503, headers={"Retry-After": "5"}))
                assert client._cooldown_until == 1005
                client._feedback(httpx.Response(429, headers={"Retry-After": "0"}))
                assert client._cooldown_until == 1005
    run(scenario())


def test_cancellation_errors_and_close_release_or_wake_waiters():
    async def scenario():
        entered = asyncio.Event()
        block = asyncio.Event()

        async def handler(request):
            if request.url.path == "/error":
                raise httpx.ConnectError("offline", request=request)
            entered.set()
            await block.wait()
            return httpx.Response(200)

        client = GuardedClient("https://bank.test", max_rps=1e9, concurrency=1,
                               transport=httpx.MockTransport(handler))
        with pytest.raises(httpx.ConnectError):
            await client.post("/error")
        assert client._active == 0
        active = asyncio.create_task(client.get("/block"))
        await entered.wait()
        cancelled = asyncio.create_task(client.get("/cancelled"))
        await settle()
        cancelled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled
        assert client._active == 1
        active.cancel()
        with pytest.raises(asyncio.CancelledError):
            await active
        assert client._active == 0
        entered.clear()
        active = asyncio.create_task(client.get("/block"))
        await entered.wait()
        queued = asyncio.create_task(client.get("/queued"))
        await settle()
        await client.aclose()
        with pytest.raises(RuntimeError, match="closed"):
            await queued
        active.cancel()
        with pytest.raises(asyncio.CancelledError):
            await active
        assert client._active == 0
    run(scenario())
