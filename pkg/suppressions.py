"""Strict external suppression files with expiry and stale-entry reporting."""
from __future__ import annotations

import copy
import re
from datetime import date, datetime
from pathlib import Path

import yaml

_FINGERPRINT = re.compile(r"^lp1:[0-9a-f]{64}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_FIELDS = {"fingerprint", "reason", "owner", "created", "expires", "ticket", "approved_by"}


def _date(value, name: str) -> date:
    if isinstance(value, datetime) or not isinstance(value, date):
        raise ValueError(f"suppression {name} must be a date")
    return value


def _mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, str) or key in result:
            raise ValueError("suppression YAML keys must be unique strings")
        result[key] = loader.construct_object(value_node, deep=True)
    return result


class _Loader(yaml.SafeLoader):
    pass


_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def load_suppressions(path, *, max_days: int = 180) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    try:
        document = yaml.load(path.read_text(encoding="utf-8"), Loader=_Loader)
    except yaml.YAMLError:
        raise ValueError("malformed suppression YAML") from None
    if isinstance(document, dict):
        if set(document) != {"suppressions"}:
            raise ValueError("suppression file has unknown fields")
        document = document["suppressions"]
    if not isinstance(document, list):
        raise ValueError("suppression file must contain a list")
    entries = []
    seen = set()
    for item in document:
        if not isinstance(item, dict) or set(item) - _FIELDS:
            raise ValueError("suppression entry has unknown or invalid fields")
        if not all(field in item for field in ("fingerprint", "reason", "owner", "created", "expires")):
            raise ValueError("suppression entry is missing a required field")
        fingerprint = item["fingerprint"]
        if not isinstance(fingerprint, str) or not _FINGERPRINT.fullmatch(fingerprint):
            raise ValueError("suppression fingerprint is invalid")
        if fingerprint in seen:
            raise ValueError("duplicate suppression fingerprint")
        seen.add(fingerprint)
        reason = item["reason"]
        if not isinstance(reason, str) or len(reason.strip()) < 20:
            raise ValueError("suppression reason must be at least 20 characters")
        owner = item["owner"]
        if not isinstance(owner, str) or not owner.strip():
            raise ValueError("suppression owner is required")
        created = _date(item["created"], "created")
        expires = _date(item["expires"], "expires")
        if expires < created or (expires - created).days > max_days:
            raise ValueError("suppression expiry exceeds the configured cap")
        for field in ("ticket", "approved_by"):
            if field in item and (not isinstance(item[field], str) or not item[field].strip()):
                raise ValueError(f"suppression {field} must be nonempty")
        entries.append({**item, "created": created, "expires": expires})
    return entries


def apply_suppressions(results, entries, *, today: date | None = None):
    today = today or date.today()
    by_fingerprint = {entry["fingerprint"]: entry for entry in entries}
    produced = set()
    active = expired = 0
    warnings = []
    output = []
    for result in results:
        copied = copy.deepcopy(result)
        fingerprint = copied.get("fingerprint")
        entry = by_fingerprint.get(fingerprint)
        if fingerprint:
            produced.add(fingerprint)
        if entry is None or copied.get("status") == "error":
            output.append(copied)
            continue
        if entry["expires"] < today:
            expired += 1
            warnings.append({"code": "suppression_expired", "owner": entry["owner"],
                             "expires": entry["expires"].isoformat()})
            output.append(copied)
            continue
        if copied.get("status") != "failed":
            output.append(copied)
            continue
        if copied.get("severity") in {"high", "critical"}:
            if not entry.get("ticket") or not entry.get("approved_by"):
                raise ValueError("high/critical suppression requires ticket and approved_by")
        copied["status"] = "suppressed"
        copied["suppression"] = {
            "owner": entry["owner"], "reason": entry["reason"],
            "expires": entry["expires"].isoformat(),
        }
        active += 1
        output.append(copied)
    stale = 0
    for fingerprint, entry in by_fingerprint.items():
        if fingerprint not in produced:
            stale += 1
            warnings.append({"code": "stale_suppression", "fingerprint": fingerprint})
    return output, {"active": active, "expired": expired, "stale": stale}, warnings
