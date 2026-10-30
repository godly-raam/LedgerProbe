from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

SPEC_PATH = Path(__file__).resolve().parent / "openapi.json"

SEEDED_DATA = {
    "tenants": {
        "owner": {"user_id": "user_owner", "token": "token-owner", "actor": "owner"},
        "other": {"user_id": "user_other", "token": "token-other", "actor": "other"},
    },
    "static_fields": {
        "currency": "USD",
        "status": "ACTIVE",
        "region": "US-EAST",
        "timestamp": "2026-10-30T00:00:00Z",
        "request_id": "req-fixed-1",
    },
    "objects": {
        "obj-owner-1": {
            "id": "obj-owner-1",
            "owner_id": "user_owner",
            "canary": "canary-secret-owner-9988",
            "nested": {
                "account": {
                    "id": "obj-owner-1",
                    "owner_id": "user_owner",
                    "canary": "canary-secret-owner-9988",
                }
            },
        },
        "obj-other-1": {
            "id": "obj-other-1",
            "owner_id": "user_other",
            "canary": "canary-secret-other-1122",
            "nested": {
                "account": {
                    "id": "obj-other-1",
                    "owner_id": "user_other",
                    "canary": "canary-secret-other-1122",
                }
            },
        },
    },
}


class AuthzServerState:
    """Per-instance state for behavior simulation, request counts, and caches."""

    def __init__(self, profile: str | None = None, fixed: bool = False, timeout_delay: float = 0.2):
        self.profile = profile
        self.fixed = fixed
        self.timeout_delay = timeout_delay
        self.request_count = 0
        self.forbidden_call_count = 0
        self.cache: dict[Any, dict] = {}


def get_identity(request: Request) -> str | None:
    """Identify the caller tenant (owner, other) or None for unauthenticated."""
    actor = request.headers.get("X-Actor")
    if actor in ("owner", "other"):
        return actor
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
        if token == "token-owner":
            return "owner"
        if token == "token-other":
            return "other"
    return None


def get_profile(request: Request) -> str:
    """Extract profile from header, query param, app state, or env var."""
    app_state: AuthzServerState = request.app.state.authz
    return (
        request.headers.get("X-Behavior-Profile")
        or request.query_params.get("behavior")
        or request.query_params.get("profile")
        or app_state.profile
        or os.environ.get("AUTHZ_BEHAVIOR")
        or os.environ.get("AUTHZ_PROFILE")
        or "bola_plain"
    )


def is_fixed(profile: str, request: Request) -> bool:
    """Determine whether the profile is operating in its fixed/safe variant."""
    app_state: AuthzServerState = request.app.state.authz
    if request.query_params.get("fixed", "").lower() in ("1", "true", "yes"):
        return True
    if os.environ.get("AUTHZ_FIXED", "").lower() in ("1", "true", "yes"):
        return True
    return app_state.fixed or profile.endswith("_fixed")


async def serve_spec(request: Request) -> JSONResponse:
    """Serve the OpenAPI specification."""
    if SPEC_PATH.exists():
        spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    else:
        spec = {"openapi": "3.0.3", "info": {"title": "Authz Fixture", "version": "1.0"}, "paths": {}}
    return JSONResponse(spec)


async def handle_object(request: Request) -> Response:
    """Handle /api/v1/objects/{id} according to the active behavior profile."""
    app_state: AuthzServerState = request.app.state.authz
    profile = get_profile(request)
    fixed = is_fixed(profile, request)
    base_profile = profile[:-6] if profile.endswith("_fixed") else profile
    identity = get_identity(request)
    obj_id = request.path_params.get("id")

    # 1. Tricky profiles evaluated before/independent of standard object dispatch
    if base_profile == "flaky_500":
        app_state.request_count += 1
        # Baseline is request 1 (200), forbidden is request 2 (200), control is request 3 (500)
        if app_state.request_count % 3 == 0:
            return JSONResponse({"error": "flaky internal server error"}, status_code=500)
        # On non-500 requests, simulate owner/forbidden response
        return JSONResponse({
            "id": "obj-owner-1",
            "canary": "canary-secret-owner-9988",
            **SEEDED_DATA["static_fields"],
        }, status_code=200)

    if base_profile == "slow_timeout":
        if identity != "owner":
            await asyncio.sleep(app_state.timeout_delay)
            return JSONResponse({"status": "ok"}, status_code=200)

    if base_profile == "rate_limit_429":
        if identity != "owner":
            return JSONResponse({"error": "rate limited"}, status_code=429, headers={"Retry-After": "0.01"})

    if base_profile == "redirect_302":
        if identity != "owner":
            return Response(status_code=302, headers={"Location": "/login", "location": "/login"})

    if base_profile == "html_login_200":
        if identity != "owner":
            return Response(
                content="<!DOCTYPE html><html><body><h1>Please sign in</h1></body></html>",
                media_type="text/html",
                status_code=200,
            )

    if base_profile == "generic_200_same_for_all":
        # Identical generic body for any id and any identity (including unauthenticated)
        return JSONResponse({"status": "ok", "service": "authz-service", "version": "1.0"}, status_code=200)

    if base_profile == "nonexistent_id_returns_200_owner_like":
        if identity is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        # Control ID collides or server returns owner-like canary and shape for any ID
        return JSONResponse({
            "id": obj_id,
            "canary": "canary-secret-owner-9988",
            **SEEDED_DATA["static_fields"],
        }, status_code=200)

    if base_profile == "invalid_control_leak_with_canary":
        if identity is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if obj_id != "obj-owner-1":
            # Negative control returns 2xx overlapping baseline static fields (>= min_unique_leaf_values) without canary
            return JSONResponse({
                "id": obj_id,
                **SEEDED_DATA["static_fields"],
            }, status_code=200)
        # Forbidden returns owner object WITH canary (actual leak)
        return JSONResponse({
            "id": "obj-owner-1",
            "canary": "canary-secret-owner-9988",
            **SEEDED_DATA["static_fields"],
        }, status_code=200)

    if base_profile == "invalid_control_leak_without_canary":
        if identity is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if obj_id != "obj-owner-1":
            # Negative control returns 2xx overlapping baseline static fields (invalid control) without canary
            return JSONResponse({
                "id": obj_id,
                **SEEDED_DATA["static_fields"],
            }, status_code=200)
        # Forbidden returns owner object attributes without canary
        return JSONResponse({
            "id": "obj-owner-1",
            **SEEDED_DATA["static_fields"],
        }, status_code=200)

    if base_profile == "nondeterministic_leak":
        if identity == "owner":
            return JSONResponse({"id": "obj-owner-1", "canary": "canary-secret-owner-9988", **SEEDED_DATA["static_fields"]}, status_code=200)
        if identity is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if obj_id != "obj-owner-1":
            return JSONResponse({"error": "not found"}, status_code=404)
        app_state.forbidden_call_count += 1
        if app_state.forbidden_call_count == 1:
            # Leaks on first forbidden request only
            return JSONResponse({"id": "obj-owner-1", "canary": "canary-secret-owner-9988", **SEEDED_DATA["static_fields"]}, status_code=200)
        # Subsequent confirmation requests fail to reproduce the leak
        return JSONResponse({"error": "forbidden"}, status_code=403)

    if base_profile == "bola_after_cache":
        if identity is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        owner_data = {"id": "obj-owner-1", "canary": "canary-secret-owner-9988", **SEEDED_DATA["static_fields"]}
        if fixed:
            # Tenant-isolated cache
            cache_key = (identity, obj_id)
            if cache_key in app_state.cache:
                return JSONResponse(app_state.cache[cache_key], status_code=200)
            if obj_id == "obj-owner-1" and identity == "owner":
                app_state.cache[cache_key] = owner_data
                return JSONResponse(owner_data, status_code=200)
            return JSONResponse({"error": "not found"}, status_code=404)
        else:
            # Vulnerable: global cache per object ID served to any authenticated identity
            cache_key = obj_id
            if cache_key in app_state.cache:
                return JSONResponse(app_state.cache[cache_key], status_code=200)
            if obj_id == "obj-owner-1" and identity == "owner":
                app_state.cache[cache_key] = owner_data
                return JSONResponse(owner_data, status_code=200)
            return JSONResponse({"error": "not found"}, status_code=404)

    # 2. Standard authentication enforcement
    if identity is None:
        if base_profile == "public_endpoint":
            return JSONResponse({"id": "pub-1", "title": "Public Guide", **SEEDED_DATA["static_fields"]}, status_code=200)
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    # 3. Nonexistent object negative control dispatch
    if obj_id != "obj-owner-1":
        if base_profile == "soft_deny_200_error_envelope":
            return JSONResponse({"error": {"code": "NOT_FOUND", "message": "Object not found"}}, status_code=200)
        if base_profile == "soft_deny_200_empty_object":
            return JSONResponse({}, status_code=200)
        if base_profile == "shared_static_fields_only":
            return JSONResponse({"currency": "USD", "status": "ACTIVE"}, status_code=200)
        return JSONResponse({"error": "not found"}, status_code=404)

    # 4. Primary baseline caller (owner requesting obj-owner-1)
    if identity == "owner":
        if base_profile == "public_endpoint":
            return JSONResponse({"id": "pub-1", "title": "Public Guide", **SEEDED_DATA["static_fields"]}, status_code=200)
        if base_profile in ("bola_nested", "bola_nested_fixed"):
            return JSONResponse({
                "currency": "USD",
                "status": "ACTIVE",
                "data": {
                    "account": {
                        "id": "obj-owner-1",
                        "owner_id": "user_owner",
                        "canary": "canary-secret-owner-9988",
                    }
                },
            }, status_code=200)
        return JSONResponse({
            "id": "obj-owner-1",
            "owner_id": "user_owner",
            "canary": "canary-secret-owner-9988",
            **SEEDED_DATA["static_fields"],
        }, status_code=200)

    # 5. Forbidden caller (other user requesting owner's object)
    if fixed:
        if base_profile == "deny_404_hide":
            return JSONResponse({"error": "not found"}, status_code=404)
        if base_profile == "deny_401":
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if base_profile == "soft_deny_200_error_envelope":
            return JSONResponse({"error": {"code": "FORBIDDEN", "message": "Access denied"}}, status_code=200)
        if base_profile == "soft_deny_200_empty_object":
            return JSONResponse({}, status_code=200)
        if base_profile == "shared_static_fields_only":
            return JSONResponse({"currency": "USD", "status": "ACTIVE"}, status_code=200)
        return JSONResponse({"error": "forbidden"}, status_code=403)

    if base_profile == "bola_plain":
        return JSONResponse({
            "id": "obj-owner-1",
            "owner_id": "user_owner",
            "canary": "canary-secret-owner-9988",
            **SEEDED_DATA["static_fields"],
        }, status_code=200)

    if base_profile == "bola_partial":
        return JSONResponse({
            "id": "obj-owner-1",
            "canary": "canary-secret-owner-9988",
            "currency": "USD",
        }, status_code=200)

    if base_profile == "bola_nested":
        return JSONResponse({
            "currency": "USD",
            "status": "ACTIVE",
            "data": {
                "account": {
                    "id": "obj-owner-1",
                    "owner_id": "user_owner",
                    "canary": "canary-secret-owner-9988",
                }
            },
        }, status_code=200)

    if base_profile == "deny_403":
        return JSONResponse({"error": "forbidden"}, status_code=403)
    if base_profile == "deny_404_hide":
        return JSONResponse({"error": "not found"}, status_code=404)
    if base_profile == "deny_401":
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if base_profile == "soft_deny_200_error_envelope":
        return JSONResponse({"error": {"code": "FORBIDDEN", "message": "Access denied"}}, status_code=200)
    if base_profile == "soft_deny_200_empty_object":
        return JSONResponse({}, status_code=200)
    if base_profile == "public_endpoint":
        return JSONResponse({"id": "pub-1", "title": "Public Guide", **SEEDED_DATA["static_fields"]}, status_code=200)
    if base_profile == "shared_static_fields_only":
        return JSONResponse({"currency": "USD", "status": "ACTIVE"}, status_code=200)

    return JSONResponse({"error": "forbidden"}, status_code=403)


async def handle_items(request: Request) -> Response:
    """Handle /api/v1/items list query endpoint."""
    profile = get_profile(request)
    fixed = is_fixed(profile, request)
    base_profile = profile[:-6] if profile.endswith("_fixed") else profile
    identity = get_identity(request)
    owner_id = request.query_params.get("owner_id")

    if identity is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    owner_items = [{
        "id": "item-owner-1",
        "owner_id": "user_owner",
        "canary": "canary-secret-owner-9988",
        **SEEDED_DATA["static_fields"],
    }]

    if base_profile == "bola_list_filter_missing":
        if fixed:
            # Caller-scoped filtering: other user asking for user_owner gets empty list
            if identity == "owner" and owner_id == "user_owner":
                return JSONResponse(owner_items, status_code=200)
            return JSONResponse([], status_code=200)
        else:
            # Vulnerable: other user asking for user_owner receives owner's items
            if owner_id == "user_owner":
                return JSONResponse(owner_items, status_code=200)
            return JSONResponse([], status_code=200)

    if base_profile in ("soft_deny_200_empty_list", "bola_list_filter_fixed"):
        if identity == "owner" and owner_id == "user_owner":
            return JSONResponse(owner_items, status_code=200)
        return JSONResponse([], status_code=200)

    return JSONResponse([], status_code=200)


async def handle_paginated(request: Request) -> Response:
    """Handle /api/v1/paginated/{id} endpoint."""
    identity = get_identity(request)
    if identity is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    catalog_id = request.path_params.get("id")
    if catalog_id != "catalog-1":
        return JSONResponse({"error": "Catalog not found"}, status_code=404)
    # The scan requests page 1 (or default). Owner canary item is located on page 2.
    return JSONResponse({
        "catalog_id": "catalog-1",
        "page": 1,
        "items": [{"id": "item-pub-header", "name": "Public Catalog"}],
    }, status_code=200)


def create_app(profile: str | None = None, fixed: bool = False, timeout_delay: float = 0.2) -> Starlette:
    """Construct an ASGI application instance configured with the specified profile."""
    app = Starlette(routes=[
        Route("/openapi.json", serve_spec, methods=["GET"]),
        Route("/api/v1/objects/{id}", handle_object, methods=["GET"]),
        Route("/api/v1/items", handle_items, methods=["GET"]),
        Route("/api/v1/paginated/{id}", handle_paginated, methods=["GET"]),
    ])
    app.state.authz = AuthzServerState(profile=profile, fixed=fixed, timeout_delay=timeout_delay)
    return app
