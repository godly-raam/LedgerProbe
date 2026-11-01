#!/usr/bin/env python3
"""Create two crAPI users and seed owner objects; write scanner inputs.

This script is part of the benchmark definition but was not executed in the
recorded run because the Docker daemon was unreachable. It is deliberately
best-effort for optional objects (video/report) and fails loudly on identities,
vehicles, orders and posts, which every rule needs.
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

OTP_RE = re.compile(r"\b(\d{4,8})\b")


def call(base: str, method: str, path: str, payload=None, token: str | None = None,
         params: dict | None = None):
    url = base.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
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
            status, _ = call(base, "GET", "/identity/api/auth/login")
            if status < 500:
                return
        except (urllib.error.URLError, TimeoutError, OSError):
            pass
        time.sleep(1)
    raise SystemExit(f"crAPI did not become ready at {base}")


def find_key(value, key):
    if isinstance(value, dict):
        if key in value:
            return value[key]
        for child in value.values():
            found = find_key(child, key)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = find_key(child, key)
            if found is not None:
                return found
    return None


def mailhog_otp(mailhog: str, email: str) -> str:
    for _ in range(30):
        status, body = call(mailhog, "GET", "/api/v2/messages")
        if status == 200:
            for item in (body or {}).get("items", []):
                recipients = item.get("To") or []
                if not any(email.lower() in json.dumps(r).lower() for r in recipients):
                    continue
                text = json.dumps(item.get("Content", {}))
                match = OTP_RE.search(text.replace("\\n", " "))
                if match:
                    return match.group(1)
        time.sleep(1)
    raise SystemExit(f"no OTP for {email} in mailhog")


def signup_and_login(base: str, mailhog: str, email: str, name: str, password: str) -> str:
    body = {"email": email, "name": name, "number": "9" + str(secrets.randbelow(10**9)),
            "password": password}
    status, response = call(base, "POST", "/identity/api/auth/signup", body)
    if status not in (200, 201):
        # A previous run may already have created the identity.
        status_login, _ = call(base, "POST", "/identity/api/auth/login",
                               {"email": email, "password": password})
        if status_login != 200:
            raise SystemExit(f"signup failed for {email}: {status} {response}")
    else:
        otp = mailhog_otp(mailhog, email)
        status, response = call(base, "POST", "/identity/api/auth/v3/check-otp",
                                {"email": email, "otp": otp, "password": password})
        if status not in (200, 201):
            raise SystemExit(f"OTP verification failed for {email}: {status} {response}")
    status, response = call(base, "POST", "/identity/api/auth/login",
                            {"email": email, "password": password})
    token = find_key(response, "token") if isinstance(response, dict) else None
    if status != 200 or not token:
        raise SystemExit(f"login failed for {email}: {status} {response}")
    return token


def owner_vehicle(base: str, token: str, vin: str) -> tuple[str, str]:
    status, response = call(base, "GET", "/identity/api/v2/vehicle/vehicles", token=token)
    if status == 200 and isinstance(response, list) and response:
        return str(response[0].get("uuid")), str(response[0].get("vin"))
    status, response = call(base, "POST", "/identity/api/v2/vehicle/add_vehicle",
                            {"vin": vin, "pincode": "1234"}, token)
    if status not in (200, 201):
        raise SystemExit(f"vehicle seed failed: {status} {response}")
    status, response = call(base, "GET", "/identity/api/v2/vehicle/vehicles", token=token)
    if status != 200 or not isinstance(response, list) or not response:
        raise SystemExit(f"vehicle readback failed: {status} {response}")
    return str(response[0].get("uuid")), str(response[0].get("vin"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--mailhog-url", default="http://127.0.0.1:8025")
    args = parser.parse_args()

    base = args.base_url
    wait_ready(base)
    suffix = secrets.token_hex(5)
    password = "LedgerProbe!42"
    owner_email = f"lp-owner-{suffix}@example.com"
    other_email = f"lp-other-{suffix}@example.com"
    owner_token = signup_and_login(base, args.mailhog_url, owner_email,
                                   f"LP Owner {suffix}", password)
    other_token = signup_and_login(base, args.mailhog_url, other_email,
                                   f"LP Other {suffix}", password)

    vin = ("LP" + suffix.upper() + secrets.token_hex(6).upper())[:17].ljust(17, "0")
    owner_vehicle_id, owner_vin = owner_vehicle(base, owner_token, vin)

    status, products = call(base, "GET", "/workshop/api/shop/products", token=owner_token)
    product_id = find_key(products, "id") if status == 200 else None
    if product_id is None:
        raise SystemExit(f"product catalogue failed: {status} {products}")
    status, order = call(base, "POST", "/workshop/api/shop/orders",
                         {"product_id": product_id, "quantity": 1}, owner_token)
    order_id = find_key(order, "id") if status == 200 else None
    if order_id is None:
        raise SystemExit(f"order seed failed: {status} {order}")

    post_canary = f"canary-crapi-post-{secrets.token_hex(8)}"
    status, post = call(base, "POST", "/community/api/v2/community/posts",
                        {"title": f"LP post {suffix}", "content": post_canary}, owner_token)
    post_id = find_key(post, "id") if status == 200 else None

    report_canary = f"canary-crapi-report-{secrets.token_hex(8)}"
    report_id = ""
    status, report = call(base, "GET", "/workshop/api/mechanic/receive_report",
                          token=owner_token,
                          params={"mechanic_code": "TRAC_JHN",
                                  "problem_details": report_canary, "vin": owner_vin})
    if status == 200:
        report_id = str(find_key(report, "id") or "")

    video_id = ""
    try:
        boundary = "----ledgerprobe" + secrets.token_hex(8)
        payload = (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
            "filename=\"ledgerprobe.mp4\"\r\nContent-Type: video/mp4\r\n\r\n"
            "ledgerprobe benchmark placeholder\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        request = urllib.request.Request(
            base.rstrip("/") + "/identity/api/v2/user/videos", data=payload,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}",
                     "Authorization": f"Bearer {owner_token}"}, method="POST")
        with urllib.request.urlopen(request, timeout=15) as response:
            video_id = str(find_key(json.loads(response.read() or b"{}"), "id") or "")
    except Exception as exc:  # optional seed; the rule will surface ERROR if absent
        print(f"[!] optional video seed skipped: {exc}")

    inputs = {
        "contexts": {
            "owner": {"Authorization": f"Bearer {owner_token}"},
            "other": {"Authorization": f"Bearer {other_token}"},
        },
        "variables": {
            "owner_email": owner_email,
            "other_email": other_email,
            "owner_vehicle_id": owner_vehicle_id,
            "owner_vin": owner_vin,
            "order_id": order_id,
            "post_id": post_id or "",
            "post_canary": post_canary,
            "report_id": report_id,
            "report_problem": report_canary,
            "video_id": video_id,
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(inputs, indent=2) + "\n", encoding="utf-8")
    args.out.chmod(0o600)
    print(f"[+] {args.instance}: crAPI inputs at {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
