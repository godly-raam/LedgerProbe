#!/usr/bin/env python3
"""Create two DVR Customers, seed owned objects, and write scanner inputs.

Tokens are obtained only to seed objects and are never persisted. The engine's
script identities re-login from the 0600 password file at scan time.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

TARGET = Path(__file__).resolve().parent


def call(base: str, method: str, path: str, payload=None,
         token: str | None = None, form: bool = False):
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        if form:
            data = urllib.parse.urlencode(payload).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(base.rstrip("/") + path, data=data,
                                     headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
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
    for _ in range(90):
        try:
            status, _ = call(base, "GET", "/healthcheck")
            if status < 500:
                return
        except (urllib.error.URLError, TimeoutError, OSError):
            pass
        time.sleep(1)
    raise SystemExit(f"DVR did not become ready at {base}")


def register(base: str, username: str, phone: str, password: str,
             first_name: str, last_name: str) -> None:
    status, body = call(base, "POST", "/register", {
        "username": username, "password": password, "phone_number": phone,
        "first_name": first_name, "last_name": last_name,
    })
    if status not in (200, 201):
        raise SystemExit(f"register failed for {username}: {status} {body}")


def login(base: str, username: str, password: str) -> str:
    status, body = call(base, "POST", "/token", {
        "grant_type": "password", "username": username, "password": password,
    }, form=True)
    token = body.get("access_token") if isinstance(body, dict) else None
    if status != 200 or not token:
        raise SystemExit(f"login failed for {username}: {status}")
    return token


def first_item(base: str, path: str, token: str):
    status, body = call(base, "GET", path, token=token)
    if status != 200:
        raise SystemExit(f"seed read failed at {path}: {status} {body}")
    return body


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    base = args.base_url
    wait_ready(base)

    suffix = secrets.token_hex(5)
    password = "LedgerProbe!42"
    owner = f"lp_owner_{suffix}"
    other = f"lp_other_{suffix}"
    owner_phone = "5551" + str(secrets.randbelow(10**6)).zfill(6)
    other_phone = "5552" + str(secrets.randbelow(10**6)).zfill(6)
    owner_first = f"Owner{suffix}"
    other_first = f"Other{suffix}"
    register(base, owner, owner_phone, password, owner_first, "Owner")
    register(base, other, other_phone, password, other_first, "Other")
    owner_token = login(base, owner, password)
    other_token = login(base, other, password)

    order_payload = {
        "delivery_address": f"lp-address-{secrets.token_hex(12)}",
        "phone_number": "5550000000",
        "items": [{"menu_item_id": 1, "quantity": 1}],
    }
    status, owner_order = call(base, "POST", "/orders", order_payload, owner_token)
    if status not in (200, 201) or not isinstance(owner_order, dict):
        raise SystemExit(f"owner order seed failed: {status} {owner_order}")
    other_payload = {
        "delivery_address": f"lp-address-{secrets.token_hex(12)}",
        "phone_number": "5550000001",
        "items": [{"menu_item_id": 1, "quantity": 1}],
    }
    status, other_order = call(base, "POST", "/orders", other_payload, other_token)
    if status not in (200, 201) or not isinstance(other_order, dict):
        raise SystemExit(f"other order seed failed: {status} {other_order}")

    status, other_ref = call(base, "GET", "/referral-code", token=other_token)
    if status != 200 or not isinstance(other_ref, dict):
        raise SystemExit(f"other referral seed failed: {status} {other_ref}")
    status, body = call(base, "POST", "/apply-referral",
                        {"referral_code": other_ref["code"]}, owner_token)
    if status != 200:
        raise SystemExit(f"owner coupon seed failed: {status} {body}")
    status, owner_ref = call(base, "GET", "/referral-code", token=owner_token)
    if status != 200 or not isinstance(owner_ref, dict):
        raise SystemExit(f"owner referral seed failed: {status} {owner_ref}")
    status, body = call(base, "POST", "/apply-referral",
                        {"referral_code": owner_ref["code"]}, other_token)
    if status != 200:
        raise SystemExit(f"other coupon seed failed: {status} {body}")

    owner_coupons = first_item(base, "/discount-coupons", owner_token)
    other_coupons = first_item(base, "/discount-coupons", other_token)
    if not isinstance(owner_coupons, list) or not owner_coupons:
        raise SystemExit("owner coupon readback was empty")
    if not isinstance(other_coupons, list) or not other_coupons:
        raise SystemExit("other coupon readback was empty")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    password_file = args.out.with_name("staging-secrets.env")
    password_file.write_text(
        f"DVR_OWNER_USERNAME={owner}\nDVR_OWNER_PASSWORD={password}\n"
        f"DVR_OTHER_USERNAME={other}\nDVR_OTHER_PASSWORD={password}\n",
        encoding="utf-8",
    )
    password_file.chmod(0o600)

    auth = {
        "schema_version": "ledgerprobe-auth/1",
        "identities": {
            name: {
                "provider": "script",
                "environment": "staging",
                "params": {
                    "argv": [sys.executable, str(TARGET / "login.py"),
                             "--identity", name,
                             "--password-file", str(password_file)],
                    "timeout": 30,
                    "env": ["PATH"],
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
            "owner_first_name": owner_first,
            "other_first_name": other_first,
            "owner_last_name": "Owner",
            "other_last_name": "Other",
            "owner_phone": owner_phone,
            "other_phone": other_phone,
            "owner_order_id": owner_order["id"],
            "other_order_id": other_order["id"],
            "owner_delivery_address": owner_order["delivery_address"],
            "other_delivery_address": other_order["delivery_address"],
            "owner_coupon_id": owner_coupons[0]["id"],
            "other_coupon_id": other_coupons[0]["id"],
            "restored_role": "Customer",
            "promoted_role": "Employee",
        },
    }
    args.out.write_text(json.dumps(inputs, indent=2) + "\n", encoding="utf-8")
    args.out.chmod(0o600)
    print(f"[+] {args.instance}: seeded {owner} / {other}; inputs at {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
