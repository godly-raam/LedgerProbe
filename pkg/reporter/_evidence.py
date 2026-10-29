"""Allowlist differential evidence before serializing it to CI reports."""
import re

_REASONS = {"leak_detected", "assertion_failed", "baseline_not_2xx", "baseline_timeout",
            "rate_limited", "server_error", "timeout", "not_reproducible", "ambiguous_2xx",
            "unexpected_status", "invalid_rule", "invalid_canary", "execution_error",
            "safety_blocked", "endpoint_absent"}


def result_properties(result):
    properties = {}
    if result.get("reason") in _REASONS:
        properties["reason"] = result["reason"]
    for name, allowed in (("verdict", {"PASS", "FAIL", "ERROR", "INCONCLUSIVE", "SKIPPED"}),
                          ("confidence", {"high", "reduced"}),
                          ("note", {"public_endpoint", "soft_deny"})):
        if result.get(name) in allowed:
            properties[name] = result[name]
    raw = result.get("evidence")
    if not isinstance(raw, dict):
        return properties
    evidence = {}
    for key in ("overlap_count", "confirm_runs"):
        if type(raw.get(key)) is int and raw[key] >= 0:
            evidence[key] = raw[key]
    for key in ("canary_matched", "nonexistent_skipped"):
        if type(raw.get(key)) is bool:
            evidence[key] = raw[key]
    controls = raw.get("control_statuses", {})
    if isinstance(controls, dict):
        evidence["control_statuses"] = {key: value for key, value in controls.items()
                                        if key in {"nonexistent_object", "unauthenticated"}
                                        and (value is None or type(value) is int and 100 <= value <= 599)}
    hashes = raw.get("shape_hashes", {})
    if isinstance(hashes, dict):
        evidence["shape_hashes"] = {key: value for key, value in hashes.items()
                                    if key in {"primary", "forbidden", "nonexistent_object", "unauthenticated"}
                                    and (value is None or isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value))}
    properties["evidence"] = evidence
    return properties
