"""Allowlist differential and race evidence before serializing it to CI reports."""
import re

_REASONS = {"unauthenticated_leak", "leak_detected", "assertion_failed", "baseline_not_2xx", "baseline_timeout", "baseline_missing_canary",
            "rate_limited", "server_error", "timeout", "not_reproducible", "ambiguous_2xx",
            "unexpected_status", "invalid_rule", "invalid_canary", "execution_error",
            "safety_blocked", "endpoint_absent", "invalid_control", "control_unusable",
            "mutation_blocked", "state_changed_by_other", "unverified_mutation",
            "verify_unavailable", "restore_failed", "race_invariant_violated",
            "weak_synchronization", "reset_failed", "overlap_without_canary"}


def result_properties(result):
    properties = {}
    if result.get("reason") in _REASONS:
        properties["reason"] = result["reason"]
    for name, allowed in (("verdict", {"PASS", "FAIL", "ERROR", "INCONCLUSIVE", "SKIPPED"}),
                          ("confidence", {"high", "reduced"}),
                          ("note", {"public_endpoint", "soft_deny", "caller_scoped", "shared_data",
                                    "control_unusable", "no_effect", "no_violation_observed",
                                    "weak_sync_mode", "h2_unavailable", "h2_coalesce_limit"})):
        if result.get(name) in allowed:
            properties[name] = result[name]
    if isinstance(result.get("spec_drift"), str) and result["spec_drift"]:
        properties["spec_drift"] = result["spec_drift"]
    if result.get("baseline_status") in {"new", "unchanged"}:
        properties["baseline_status"] = result["baseline_status"]
    if result.get("status") == "suppressed" and isinstance(result.get("suppression"), dict):
        suppression = result["suppression"]
        properties["suppressed"] = True
        if isinstance(suppression.get("owner"), str) and suppression["owner"]:
            properties["suppression_owner"] = suppression["owner"]
    raw = result.get("evidence")
    if not isinstance(raw, dict):
        return properties
    evidence = {}
    for key in ("overlap_count", "confirm_runs", "pages_walked", "mutation_status", "probe_status",
                "rounds_executed", "strong_rounds", "violating_rounds", "rate_limited_count",
                "server_error_count", "timeout_count", "verify_unavailable_count",
                "max_successes", "max_total_effect", "first_violation_round"):
        if type(raw.get(key)) is int and raw[key] >= 0:
            evidence[key] = raw[key]
    for key in ("canary_matched", "nonexistent_skipped", "control_unusable",
                "changed", "probe_matched", "restore_failed", "reset_failed",
                "verify_unavailable"):
        if type(raw.get(key)) is bool:
            evidence[key] = raw[key]
    for key in ("median_spread_ms", "hit_rate"):
        value = raw.get(key)
        if type(value) in (int, float) and not isinstance(value, bool) and value >= 0:
            evidence[key] = value
    accepted = raw.get("accepted_counts")
    if (isinstance(accepted, list) and len(accepted) <= 20
            and all(type(value) is int and value >= 0 for value in accepted)):
        evidence["accepted_counts"] = accepted
    if raw.get("scope") in {"object", "caller", "shared"}:
        evidence["scope"] = raw["scope"]
    if raw.get("verification_mode") in {"marker", "probe", "state_diff"}:
        evidence["verification_mode"] = raw["verification_mode"]
    if raw.get("sync_mode") in {"last_byte", "h2_single_packet", "burst"}:
        evidence["sync_mode"] = raw["sync_mode"]
    if raw.get("idempotency_mode") in {"same", "unique", "none"}:
        evidence["idempotency_mode"] = raw["idempotency_mode"]
    if raw.get("sync_note") in {"weak_sync_mode", "h2_unavailable", "h2_coalesce_limit"}:
        evidence["sync_note"] = raw["sync_note"]
    for key in ("marker_hash", "before_hash", "after_hash"):
        value = raw.get(key)
        if isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value):
            evidence[key] = value
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
