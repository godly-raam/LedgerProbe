#!/usr/bin/env python3
"""Form-login bridge for DVR's OAuth2 /token endpoint.

LedgerProbe's login_request provider sends JSON. DVR's FastAPI endpoint accepts
OAuth2PasswordRequestForm, so this narrow adapter performs the form login and
returns only an in-memory token to the engine's script provider.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True)
    parser.add_argument("--password-file", required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:8091")
    args = parser.parse_args()

    values = read_env(Path(args.password_file))
    username = values.get(f"DVR_{args.identity.upper()}_USERNAME")
    password = values.get(f"DVR_{args.identity.upper()}_PASSWORD")
    if not username or not password:
        return 1
    payload = urllib.parse.urlencode(
        {"grant_type": "password", "username": username, "password": password}
    ).encode("utf-8")
    request = urllib.request.Request(
        args.base_url.rstrip("/") + "/token", data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError,
            ValueError, OSError):
        return 1
    token = body.get("access_token") if isinstance(body, dict) else None
    if not isinstance(token, str) or not token:
        return 1
    print(json.dumps({"headers": {"Authorization": "Bearer " + token},
                      "expires_in": 1800}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
