#!/usr/bin/env python3
"""Create two VAmPI users and an owner book; write scanner inputs.

Only the standard library is used so the setup can run inside the benchmark
virtualenv without adding target dependencies.
"""

from __future__ import annotations

import argparse
import json
import secrets
import time
import urllib.error
import urllib.request
from pathlib import Path


def call(base: str, method: str, path: str, payload=None, token: str | None = None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(base.rstrip("/") + path, data=data,
                                     headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read().decode("utf-8", "replace")
            status = response.status
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        status = exc.code
    try:
        parsed = json.loads(body) if body else None
    except json.JSONDecodeError:
        parsed = body
    return status, parsed


def wait_ready(base: str) -> None:
    for _ in range(60):
        try:
            status, _ = call(base, "GET", "/")
            if status < 500:
                return
        except (urllib.error.URLError, TimeoutError, OSError):
            pass
        time.sleep(1)
    raise SystemExit(f"VAmPI did not become ready at {base}")


def login(base: str, username: str, password: str) -> str:
    status, body = call(base, "POST", "/users/v1/login",
                        {"username": username, "password": password})
    if status != 200 or not isinstance(body, dict) or not body.get("auth_token"):
        raise SystemExit(f"login failed for {username}: {status} {body}")
    return body["auth_token"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    base = args.base_url
    wait_ready(base)
    # /createdb is the upstream reset/populate route. Each instance owns its
    # own SQLite database, so resetting here cannot affect the other mode.
    status, body = call(base, "GET", "/createdb")
    if status != 200:
        raise SystemExit(f"createdb failed: {status} {body}")

    suffix = secrets.token_hex(5)
    owner = f"lp_owner_{suffix}"
    other = f"lp_other_{suffix}"
    owner_email = f"owner-{suffix}@ledgerprobe.test"
    other_email = f"other-{suffix}@ledgerprobe.test"
    password = "LedgerProbe!42"
    book_title = f"owner-book-{suffix}"
    canary = f"canary-vampi-{secrets.token_hex(12)}"

    for username, email in ((owner, owner_email), (other, other_email)):
        status, body = call(base, "POST", "/users/v1/register",
                            {"username": username, "password": password, "email": email})
        if status != 200:
            raise SystemExit(f"register failed for {username}: {status} {body}")

    owner_token = login(base, owner, password)

    status, body = call(base, "POST", "/books/v1",
                        {"book_title": book_title, "secret": canary}, owner_token)
    if status != 200:
        raise SystemExit(f"book seed failed: {status} {body}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    password_file = args.out.with_name("staging-secrets.env")
    password_file.write_text(f"VAMPI_PASSWORD={password}\n", encoding="utf-8")
    password_file.chmod(0o600)
    auth = {
        "schema_version": "ledgerprobe-auth/1",
        "identities": {
            name: {
                "provider": "login_request",
                "environment": "staging",
                "params": {
                    "method": "POST",
                    "path": "/users/v1/login",
                    "body": {"username": "{{%s_username}}" % name,
                             "password_ref": f"file:{password_file}#VAMPI_PASSWORD"},
                    "token_json_path": "auth_token",
                    "header_format": "Bearer {token}",
                },
            }
            for name in ("owner", "other")
        },
    }
    args.out.with_name("ledgerprobe-auth.yaml").write_text(
        json.dumps(auth, indent=2) + "\n", encoding="utf-8")
    inputs = {
        "variables": {
            "owner_username": owner,
            "other_username": other,
            "owner_email": owner_email,
            "other_email": other_email,
            "book_title": book_title,
            "canary_value": canary,
            "original_password": password,
            "new_password": "LedgerProbe!43",
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(inputs, indent=2) + "\n", encoding="utf-8")
    args.out.chmod(0o600)
    print(f"[+] {args.instance}: seeded {owner} / {other}; auth at ledgerprobe-auth.yaml")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
