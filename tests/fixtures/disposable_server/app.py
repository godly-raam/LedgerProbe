from __future__ import annotations

import copy
import itertools
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

DISPOSABLE_SENTINEL = "lpsentineldisposable7731"
TOKENS = {"Bearer token-owner": "owner", "Bearer token-user": "user",
          "Bearer token-admin": "admin"}


class DisposableState:
    def __init__(self, profile: str = "disposable_delete_fixed", kill_file: Path | None = None):
        self.profile = profile
        self.kill_file = kill_file
        self.ids = itertools.count(1)
        self.items = {"item-owner-1": {"id": "item-owner-1", "owner": "owner",
                                        "name": "pre-existing"}}
        self.resources: dict[str, dict] = {}
        self.users = {"user-owner-1": {"id": "user-owner-1", "name": "owner",
                                         "is_admin": False}}
        self.requests: list[tuple[str, str, str | None]] = []

    def next_id(self, prefix: str) -> str:
        return f"{prefix}-{DISPOSABLE_SENTINEL}-{next(self.ids)}"


def identity(request: Request) -> str | None:
    return TOKENS.get(request.headers.get("Authorization", ""))


def record(request: Request) -> None:
    request.app.state.disposable.requests.append(
        (request.method, request.url.path, identity(request)))


async def create_item(request: Request) -> JSONResponse:
    state = request.app.state.disposable
    record(request)
    actor = identity(request)
    if state.profile == "fixture_creation_fails":
        return JSONResponse({"error": "fixture creation failed"}, status_code=500)
    if actor not in {"owner", "admin"}:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    item_id = state.next_id("item")
    body = await request.json()
    state.items[item_id] = {"id": item_id, "owner": actor,
                            "name": body.get("name", "fixture")}
    if state.profile == "kill_switch_during_attack" and state.kill_file is not None:
        state.kill_file.write_text("stop", encoding="utf-8")
    if state.profile == "capture_missing":
        return JSONResponse({"ok": True}, status_code=201)
    return JSONResponse({"id": item_id}, status_code=201)


async def get_item(request: Request) -> JSONResponse:
    state = request.app.state.disposable
    record(request)
    item = state.items.get(request.path_params["id"])
    if item is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(copy.deepcopy(item))


async def delete_item(request: Request) -> JSONResponse:
    state = request.app.state.disposable
    record(request)
    item_id = request.path_params["id"]
    item = state.items.get(item_id)
    if item is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    actor = identity(request)
    if actor is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if state.profile == "cleanup_failure" and actor == "owner":
        return JSONResponse({"error": "cleanup failed"}, status_code=500)
    if state.profile == "disposable_delete_fixed" and actor == "user":
        return JSONResponse({"error": "forbidden"}, status_code=403)
    if actor not in {"owner", "admin", "user"}:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    if state.profile not in {"disposable_delete_noop", "cleanup_failure"}:
        state.items.pop(item_id, None)
    return JSONResponse({"deleted": True})


async def create_resource(request: Request) -> JSONResponse:
    state = request.app.state.disposable
    record(request)
    actor = identity(request)
    if state.profile == "disposable_create_fixed" and actor != "admin":
        return JSONResponse({"error": "forbidden"}, status_code=403)
    resource_id = state.next_id("resource")
    body = await request.json()
    state.resources[resource_id] = {"id": resource_id, "name": body.get("name")}
    return JSONResponse({"id": resource_id}, status_code=201)


async def get_resource(request: Request) -> JSONResponse:
    state = request.app.state.disposable
    record(request)
    if identity(request) != "admin":
        return JSONResponse({"error": "forbidden"}, status_code=403)
    resource = state.resources.get(request.path_params["id"])
    if resource is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(copy.deepcopy(resource))


async def delete_resource(request: Request) -> JSONResponse:
    state = request.app.state.disposable
    record(request)
    if identity(request) != "admin":
        return JSONResponse({"error": "forbidden"}, status_code=403)
    resource_id = request.path_params["id"]
    if state.resources.pop(resource_id, None) is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse({"deleted": True})


async def register_user(request: Request) -> JSONResponse:
    state = request.app.state.disposable
    record(request)
    if identity(request) is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    body = await request.json()
    user_id = state.next_id("user")
    privileged = bool(body.get("is_admin"))
    if state.profile == "register_mass_assignment_fixed":
        privileged = False
    state.users[user_id] = {"id": user_id, "name": body.get("name"),
                            "is_admin": privileged}
    return JSONResponse({"id": user_id}, status_code=201)


async def get_user(request: Request) -> JSONResponse:
    state = request.app.state.disposable
    record(request)
    if identity(request) != "admin":
        return JSONResponse({"error": "forbidden"}, status_code=403)
    user = state.users.get(request.path_params["id"])
    if user is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(copy.deepcopy(user))


async def delete_user(request: Request) -> JSONResponse:
    state = request.app.state.disposable
    record(request)
    if identity(request) != "admin":
        return JSONResponse({"error": "forbidden"}, status_code=403)
    user_id = request.path_params["id"]
    if state.users.pop(user_id, None) is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse({"deleted": True})


async def health(request: Request) -> JSONResponse:
    record(request)
    return JSONResponse({"ok": True})


def create_app(profile: str = "disposable_delete_fixed", kill_file: Path | None = None):
    app = Starlette(routes=[
        Route("/api/v1/items", create_item, methods=["POST"]),
        Route("/api/v1/items/{id}", get_item, methods=["GET"]),
        Route("/api/v1/items/{id}", delete_item, methods=["DELETE"]),
        Route("/api/v1/admin/resources", create_resource, methods=["POST"]),
        Route("/api/v1/admin/resources/{id}", get_resource, methods=["GET"]),
        Route("/api/v1/admin/resources/{id}", delete_resource, methods=["DELETE"]),
        Route("/api/v1/users", register_user, methods=["POST"]),
        Route("/api/v1/users/{id}", get_user, methods=["GET"]),
        Route("/api/v1/users/{id}", delete_user, methods=["DELETE"]),
        Route("/api/v1/health", health, methods=["GET"]),
    ])
    app.state.disposable = DisposableState(profile=profile, kill_file=kill_file)
    return app