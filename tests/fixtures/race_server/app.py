from __future__ import annotations

import asyncio
import os

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route


class RaceState:
    def __init__(self, profile: str):
        self.profile = profile
        self.lock = asyncio.Lock()
        self.reset_attempts = 0
        self._fresh()

    def _fresh(self):
        self.balance = 10
        self.ledger = 0
        self.coupon_uses = 0
        self.idempotency_keys: set[str] = set()

    def reset(self):
        self._fresh()


def state(request: Request) -> RaceState:
    return request.app.state.race


def profile(request: Request) -> str:
    return os.environ.get("RACE_PROFILE", state(request).profile)


async def health(request: Request):
    return JSONResponse({"ok": True, "profile": profile(request)})


async def reset(request: Request):
    app_state = state(request)
    app_state.reset_attempts += 1
    if profile(request) == "reset_failure" and app_state.reset_attempts == 1:
        return JSONResponse({"error": "reset failed"}, status_code=500)
    app_state.reset()
    return JSONResponse({"ok": True})


async def wallet(request: Request):
    app_state = state(request)
    return JSONResponse({"balance": app_state.balance, "ledger": app_state.ledger})


async def coupon_state(request: Request):
    return JSONResponse({"uses": state(request).coupon_uses})


async def _amount(request: Request) -> int:
    try:
        payload = await request.json()
    except Exception:
        return 0
    if not isinstance(payload, dict):
        return 0
    amount = payload.get("amount", 10)
    return amount if type(amount) is int and amount > 0 else 0


async def wallet_spend(request: Request):
    app_state = state(request)
    if profile(request) == "rate_limit_429_during_race":
        return JSONResponse({"error": "rate limited"}, status_code=429,
                            headers={"Retry-After": "0.01"})
    amount = await _amount(request)
    if not amount:
        return JSONResponse({"error": "bad amount"}, status_code=400)
    if profile(request) == "wallet_race_vulnerable":
        if app_state.balance >= amount:
            await asyncio.sleep(0.03)
            app_state.balance -= amount
            app_state.ledger += amount
            return JSONResponse({"accepted": True}, status_code=200)
        return JSONResponse({"accepted": False}, status_code=409)
    async with app_state.lock:
        if app_state.balance >= amount:
            app_state.balance -= amount
            app_state.ledger += amount
            return JSONResponse({"accepted": True}, status_code=200)
    return JSONResponse({"accepted": False}, status_code=409)


async def coupon_redeem(request: Request):
    app_state = state(request)
    if profile(request) == "coupon_single_use_vulnerable":
        if app_state.coupon_uses == 0:
            await asyncio.sleep(0.03)
        app_state.coupon_uses += 1
        return JSONResponse({"accepted": True}, status_code=200)
    async with app_state.lock:
        if app_state.coupon_uses:
            return JSONResponse({"accepted": False}, status_code=409)
        app_state.coupon_uses = 1
        return JSONResponse({"accepted": True}, status_code=200)


async def idempotent_spend(request: Request):
    app_state = state(request)
    amount = await _amount(request)
    key = request.headers.get("idempotency-key")
    if not amount or not key:
        return JSONResponse({"error": "bad request"}, status_code=400)
    if profile(request) == "idempotency_key_ignored":
        await asyncio.sleep(0.03)
        app_state.balance -= amount
        app_state.ledger += amount
        return JSONResponse({"accepted": True}, status_code=200)
    async with app_state.lock:
        if key in app_state.idempotency_keys:
            return JSONResponse({"accepted": False}, status_code=409)
        app_state.idempotency_keys.add(key)
        app_state.balance -= amount
        app_state.ledger += amount
        return JSONResponse({"accepted": True}, status_code=200)


state.profile = None
app = Starlette(routes=[
    Route("/race/health", health, methods=["GET"]),
    Route("/race/reset", reset, methods=["POST"]),
    Route("/race/wallet", wallet, methods=["GET"]),
    Route("/race/coupon", coupon_state, methods=["GET"]),
    Route("/race/wallet/spend", wallet_spend, methods=["POST"]),
    Route("/race/coupon/redeem", coupon_redeem, methods=["POST"]),
    Route("/race/idempotency/spend", idempotent_spend, methods=["POST"]),
])
app.state.race = RaceState(os.environ.get("RACE_PROFILE", "wallet_race_safe"))
