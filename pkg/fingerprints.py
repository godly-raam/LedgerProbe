"""Stable finding fingerprints shared by JSON, SARIF, JUnit, and baselines."""
from __future__ import annotations

import hashlib
import json

CHECK_TYPES = {
    "bola", "state_change", "race", "unauthenticated_access",
    "caller_scope", "shared_scope",
}


def check_type(rule: dict) -> str:
    if "race" in rule:
        return "race"
    if rule.get("mutating"):
        return "state_change"
    if "leak_detection" in rule:
        scope = rule.get("scope", "object")
        if scope == "caller":
            return "caller_scope"
        if scope == "shared":
            return "shared_scope"
        return "bola"
    roles = rule.get("auth_contexts", {})
    if not roles.get("primary"):
        return "unauthenticated_access"
    return "bola"


def identity_roles(rule: dict) -> list[str]:
    roles = set(rule.get("auth_contexts", {}).values())
    race_identity = (rule.get("race") or {}).get("identity")
    if race_identity and race_identity in roles:
        roles.add(race_identity)
    return sorted(roles)


def fingerprint(*, rule_id: str, method: str, path_template: str,
                identity_roles=(), check_type: str) -> str:
    if check_type not in CHECK_TYPES:
        raise ValueError("unknown check type")
    document = {
        "rule_id": rule_id,
        "method": method,
        "path_template": path_template,
        "identity_roles": sorted(identity_roles),
        "check_type": check_type,
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True)
    return "lp1:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def result_fingerprint(result: dict) -> str:
    if isinstance(result.get("fingerprint"), str):
        return result["fingerprint"]
    return fingerprint(
        rule_id=result.get("rule_id", "unknown"),
        method=result.get("method", "GET"),
        path_template=result.get("path_template", result.get("path", "")),
        identity_roles=result.get("identity_roles", ()),
        check_type=result.get("check_type", "bola"),
    )
