"""Pure differential authorization verdicts. Raw observations never enter results."""
from __future__ import annotations

import hashlib
import json
from typing import Any


def _typed(value: Any) -> str:
    return json.dumps([type(value).__name__, value], sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


def _leaves(value: Any, ignored: set[str], path: str = "") -> dict[str, str]:
    if path in ignored:
        return {}
    if isinstance(value, (dict, list)):
        children = value.items() if isinstance(value, dict) else enumerate(value)
        leaves = {}
        for key, child in children:
            leaves.update(_leaves(child, ignored, f"{path}.{key}" if path else str(key)))
        return leaves
    return {path: _typed(value)}


def _values(response: dict | None, ignored: set[str]) -> set[str]:
    return set(_leaves(response["body"], ignored).values()) if response and "body" in response else set()


def _shape(response: dict | None, ignored: set[str]) -> str | None:
    if response is None or "body" not in response:
        return None
    # Include empty containers so {} and [] are not the same shape. Hash only
    # paths/types, never scalar values (including low-entropy object IDs).
    def structure(value, path=""):
        if path in ignored:
            return []
        entries = [(path, type(value).__name__)]
        if isinstance(value, (dict, list)):
            children = value.items() if isinstance(value, dict) else enumerate(value)
            for key, child in children:
                entries.extend(structure(child, f"{path}.{key}" if path else str(key)))
        return entries
    shape = sorted(structure(response["body"]))
    return hashlib.sha256(json.dumps(shape, separators=(",", ":")).encode()).hexdigest()


def _same_data(left: dict, right: dict, ignored: set[str]) -> bool:
    if "body" not in left or "body" not in right:
        return False
    a, b = _leaves(left["body"], ignored), _leaves(right["body"], ignored)
    return bool(a) and a == b and _shape(left, ignored) == _shape(right, ignored)


def _problem(response: dict | None) -> str | None:
    if response is None:
        return None
    if response.get("error") == "timeout":
        return "timeout"
    status = response.get("status", 0)
    if status == 429:
        return "rate_limited"
    if 500 <= status < 600:
        return "server_error"
    return None


def _unusable_control(response: dict | None) -> bool:
    """A control that never produced a usable negative observation."""
    if response is None:
        return False
    if response.get("error") == "timeout":
        return True
    status = response.get("status", 0)
    return status == 429 or 500 <= status < 600


def _output(status, verdict, message, *, reason=None, note=None, confidence="reduced", evidence=None):
    output = {"status": status, "verdict": verdict, "message": message,
              "confidence": confidence, "evidence": evidence or {}}
    if reason:
        output["reason"] = reason
    if note:
        output["note"] = note
    return output


def _scoped_result(scope: str, *, baseline: dict, forbidden: dict, acceptable_status,
                   canaries, min_unique_leaf_values: int, ignore_fields,
                   confirm: int, confirm_responses, require_owner_canary_in_baseline: bool) -> dict:
    """Evaluate a rule whose declared scope is caller or shared.

    These scopes deliberately do not use a nonexistent-object control: their
    contract is about what another authenticated identity receives, not about
    whether an arbitrary missing object is hidden.
    """
    ignored = set(ignore_fields)
    confirmations = list(confirm_responses)
    base_values = _values(baseline, ignored)
    foreign_values = _values(forbidden, ignored)
    declared_canaries = {_typed(value) for value in canaries}
    canary_values = declared_canaries & base_values
    hits = canary_values & foreign_values
    overlap = base_values & foreign_values
    evidence = {
        "scope": scope, "overlap_count": len(overlap), "canary_matched": bool(hits),
        "control_statuses": {"nonexistent_object": None,
                             "unauthenticated": (forbidden or {}).get("status")},
        "nonexistent_skipped": True, "confirm_runs": 0,
        "shape_hashes": {name: _shape(observation, ignored) for name, observation in (
            ("primary", baseline), ("forbidden", forbidden))},
    }
    confidence = "high" if canary_values else "reduced"

    def result(status, reason=None, note=None):
        messages = {
            "baseline_not_2xx": "Primary baseline did not return 2xx.",
            "baseline_timeout": "Primary baseline timed out.",
            "baseline_missing_canary": "Primary baseline did not contain a required owner canary.",
            "rate_limited": "Authorization evidence was rate limited.",
            "server_error": "Authorization evidence received a server error.",
            "timeout": "Authorization evidence timed out.",
            "not_reproducible": "Leak evidence could not be reproduced on every confirmation.",
            "leak_detected": "Forbidden response reproducibly exposed owner-object evidence.",
            "ambiguous_2xx": "Successful response is empty or unparseable.",
            "unexpected_status": "Forbidden response returned an unexpected status.",
            "caller_scoped": "Successful response is scoped to the requesting identity with no owner evidence.",
            "shared_data": "Successful response contains shared non-owner data.",
        }
        verdict = {"passed": "PASS", "failed": "FAIL", "inconclusive": "INCONCLUSIVE", "error": "ERROR"}[status]
        output = _output(status, verdict, messages.get(reason or note, "Forbidden request was denied."),
                         reason=reason, note=note, confidence=confidence, evidence=evidence)
        return output

    if baseline.get("error") == "timeout":
        return result("error", "baseline_timeout")
    if not 200 <= baseline.get("status", 0) < 300:
        return result("error", "baseline_not_2xx")
    if require_owner_canary_in_baseline and not canary_values:
        return result("error", "baseline_missing_canary")
    problem = _problem(forbidden)
    if problem:
        return result("inconclusive", problem)
    status = forbidden.get("status", 0)
    if status in set(acceptable_status) and not 200 <= status < 300:
        return result("passed")
    if not 200 <= status < 300:
        return result("inconclusive", "unexpected_status")

    def confirmed(values: set[str], allow_subset: bool) -> str | None:
        stable = set(values)
        for observation in confirmations:
            problem = _problem(observation)
            if problem:
                return problem
            if not 200 <= observation.get("status", 0) < 300:
                return "not_reproducible"
            present = _values(observation, ignored)
            stable &= present
            if not stable:
                return "not_reproducible"
            if not allow_subset and stable != values:
                return "not_reproducible"
        if len(confirmations) != confirm:
            return "not_reproducible"
        return None

    if scope == "caller":
        # A caller-scoped endpoint is safe when the other identity receives a
        # successful, non-empty body without owner evidence. An empty body is
        # ambiguous, not a vacuous pass.
        body = forbidden.get("body")
        if body is None or not _leaves(body, ignored):
            return result("inconclusive", "ambiguous_2xx")
        candidate = bool(hits) or len(overlap) >= min_unique_leaf_values
        if not candidate:
            return result("passed", note="caller_scoped")
        failure = confirmed(hits or overlap, allow_subset=False)
        if failure:
            return result("inconclusive", failure)
        evidence.update(overlap_count=len(overlap), canary_matched=bool(hits),
                        confirm_runs=len(confirmations))
        return result("failed", "leak_detected")

    if scope == "shared":
        # A shared catalogue must not contain owner-specific canaries. If the
        # owner baseline contains one, emitting it to another identity is a leak;
        # the absence of that canary is the positive PASS condition.
        if hits:
            failure = confirmed(hits, allow_subset=True)
            if failure:
                return result("inconclusive", failure)
            evidence.update(canary_matched=True, confirm_runs=len(confirmations))
            return result("failed", "leak_detected")
        if canary_values:
            return result("inconclusive", "ambiguous_2xx")
        return result("passed", note="shared_data")

    return result("inconclusive", "ambiguous_2xx")


def evaluate_scoped(*, scope: str, baseline: dict, forbidden: dict,
                     acceptable_status=(401, 403, 404), canaries=(),
                     min_unique_leaf_values: int = 2, ignore_fields=(),
                     confirm: int = 2, confirm_responses=(),
                     require_owner_canary_in_baseline: bool = False) -> dict:
    """Evaluate a caller- or shared-scoped endpoint."""
    if scope not in {"caller", "shared"}:
        raise ValueError("scope must be caller or shared")
    return _scoped_result(scope, baseline=baseline, forbidden=forbidden,
                          acceptable_status=acceptable_status, canaries=canaries,
                          min_unique_leaf_values=min_unique_leaf_values,
                          ignore_fields=ignore_fields, confirm=confirm,
                          confirm_responses=confirm_responses,
                          require_owner_canary_in_baseline=require_owner_canary_in_baseline)


def evaluate_differential(*, baseline: dict, forbidden: dict,
                          acceptable_status=(401, 403, 404), canaries=(),
                          min_unique_leaf_values: int = 2, ignore_fields=(),
                          nonexistent: dict | None = None, unauthenticated: dict | None = None,
                          nonexistent_skipped: bool = False, confirm: int = 2,
                          confirm_responses=()) -> dict:
    """Evaluate JSON observations, without I/O, randomness, or raw evidence output.

    An observation has ``status`` and optional decoded JSON ``body``; a timeout
    has ``error: timeout`` instead. Only candidate leaks require ``confirm``
    additional observations. Call with confirm=0 for a provisional classification.
    """
    ignored = set(ignore_fields)
    confirmations = list(confirm_responses)
    base_values = _values(baseline, ignored)
    foreign_values = _values(forbidden, ignored)
    control_unusable = _unusable_control(nonexistent)
    absent_values = set() if control_unusable else _values(nonexistent, ignored)
    declared_canaries = {_typed(value) for value in canaries}
    canary_values = declared_canaries & base_values
    has_negative_control = nonexistent is not None and "body" in nonexistent and not control_unusable
    control_overlap = base_values & absent_values
    canary_in_control = bool(declared_canaries & absent_values) and not control_unusable
    control_status = nonexistent.get("status", 0) if nonexistent else 0
    invalid_control = bool(
        nonexistent
        and "body" in nonexistent
        and not control_unusable
        and 200 <= control_status < 300
        and (len(control_overlap) >= min_unique_leaf_values or canary_in_control)
    )
    valid_negative_control = has_negative_control and not invalid_control
    # A failed negative control cannot label owner values as generic/shared.
    subtract_values = set() if invalid_control or control_unusable else absent_values
    overlap = (base_values & foreign_values) - subtract_values
    # Explicit owner canaries can independently prove a leak, but a canary also
    # returned for the nonexistent ID is no longer owner-specific evidence.
    hits = canary_values & foreign_values - absent_values
    evidence = {
        "overlap_count": len(overlap), "canary_matched": bool(hits),
        "control_statuses": {"nonexistent_object": (nonexistent or {}).get("status"),
                             "unauthenticated": (unauthenticated or {}).get("status")},
        "nonexistent_skipped": nonexistent_skipped,
        "control_unusable": control_unusable,
        "confirm_runs": len(confirmations),
        "shape_hashes": {name: _shape(observation, ignored) for name, observation in (
            ("primary", baseline), ("forbidden", forbidden),
            ("nonexistent_object", nonexistent), ("unauthenticated", unauthenticated))},
    }

    def result(status, reason=None, note=None):
        verdict = {"passed": "PASS", "failed": "FAIL", "inconclusive": "INCONCLUSIVE", "error": "ERROR"}[status]
        messages = {
            "baseline_not_2xx": "Primary baseline did not return 2xx.",
            "baseline_timeout": "Primary baseline timed out.",
            "rate_limited": "Authorization evidence was rate limited.",
            "server_error": "Authorization evidence received a server error.",
            "timeout": "Authorization evidence timed out.",
            "not_reproducible": "Leak evidence could not be reproduced on every confirmation.",
            "leak_detected": "Forbidden response reproducibly exposed owner-object evidence.",
            "ambiguous_2xx": "Successful response has insufficient owner-specific leak evidence.",
            "unexpected_status": "Forbidden response returned an unexpected status.",
            "public_endpoint": "Unauthenticated callers receive the same data; endpoint appears public.",
            "soft_deny": "Response matches the nonexistent-object response shape without leak evidence.",
            "invalid_control": "Nonexistent-object negative control response is invalid.",
            "control_unusable": "Nonexistent-object control was unusable; leak evidence was evaluated without it.",
            "unauthenticated_leak": "Unauthenticated response exposed owner-object evidence.",
        }
        output = {"status": status, "verdict": verdict,
                  "message": messages.get(reason or note, "Forbidden request was denied."),
                  "confidence": "high" if valid_negative_control and unauthenticated is not None else "reduced",
                  "evidence": evidence}
        if reason:
            output["reason"] = reason
        if note:
            output["note"] = note
        return output

    if baseline.get("error") == "timeout":
        return result("error", "baseline_timeout")
    if not 200 <= baseline.get("status", 0) < 300:
        return result("error", "baseline_not_2xx")
    problem = _problem(forbidden)
    if problem:
        return result("inconclusive", problem)
    status = forbidden.get("status", 0)
    accepted_deny = status in acceptable_status
    if not accepted_deny and not 200 <= status < 300:
        return result("inconclusive", "unexpected_status")
    # An unhealthy unauthenticated control still blocks an otherwise ambiguous
    # verdict. An unusable *nonexistent-object* control is handled below: it is
    # weaker evidence, not a verdict-level server error.
    for control in (unauthenticated,):
        problem = _problem(control)
        if problem:
            return result("inconclusive", problem)
    unauth_values = _values(unauthenticated, ignored)
    unauth_overlap = (base_values & unauth_values) - absent_values
    unauth_canary = bool(canary_values & unauth_values - absent_values)
    anonymous_leak = bool(unauthenticated and 200 <= unauthenticated.get("status", 0) < 300 and (
        unauth_canary or (valid_negative_control and len(unauth_overlap) >= min_unique_leaf_values)))
    if anonymous_leak:
        overlap = unauth_overlap
        hits = canary_values & unauth_values - absent_values
        evidence.update(overlap_count=len(overlap), canary_matched=bool(hits))
    if accepted_deny and not anonymous_leak:
        return result("passed")
    if (not anonymous_leak and not canary_in_control and unauthenticated and 200 <= unauthenticated.get("status", 0) < 300
            and _same_data(forbidden, unauthenticated, ignored) and not control_unusable):
        return result("passed", note="public_endpoint")
    if control_unusable:
        # A 5xx/429/timed-out negative control cannot certify generic overlap or
        # a soft deny. An explicit owner canary in the forbidden 2xx response is
        # still independent evidence, but the finding is reduced-confidence and
        # carries the control_unusable note.
        if hits:
            stable_hits = set(hits)
            for observation in confirmations:
                problem = _problem(observation)
                if problem:
                    return result("inconclusive", problem)
                if not 200 <= observation.get("status", 0) < 300:
                    return result("inconclusive", "not_reproducible")
                stable_hits &= _values(observation, ignored)
            if len(confirmations) != confirm or not stable_hits:
                return result("inconclusive", "not_reproducible")
            evidence.update(canary_matched=True, confirm_runs=len(confirmations))
            return result("failed", "leak_detected", note="control_unusable")
        return result("inconclusive", "control_unusable")
    if invalid_control and not hits:
        return result("inconclusive", "invalid_control")
    # Without a usable negative control generic/static overlap is not evidence.
    candidate = anonymous_leak or bool(hits) or (valid_negative_control and len(overlap) >= min_unique_leaf_values)
    if candidate:
        stable_overlap, stable_hits = set(overlap), set(hits)
        for observation in confirmations:
            problem = _problem(observation)
            if problem:
                return result("inconclusive", problem)
            if not 200 <= observation.get("status", 0) < 300:
                return result("inconclusive", "not_reproducible")
            confirmed = (_values(observation, ignored) & base_values) - subtract_values
            stable_overlap &= confirmed
            stable_hits &= confirmed
            if not (stable_hits or (valid_negative_control and len(stable_overlap) >= min_unique_leaf_values
                                    and stable_overlap == overlap)):
                return result("inconclusive", "not_reproducible")
        if len(confirmations) != confirm:
            return result("inconclusive", "not_reproducible")
        return result("failed", "unauthenticated_leak" if anonymous_leak else "leak_detected")
    if invalid_control:
        return result("inconclusive", "invalid_control")
    if (valid_negative_control and "body" in forbidden
            and _shape(forbidden, ignored) == _shape(nonexistent, ignored)):
        return result("passed", note="soft_deny")
    return result("inconclusive", "ambiguous_2xx")
