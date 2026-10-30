"""Pure verdict scenarios use synthetic object data, never credentials or a target."""
import copy
import json

import pytest

from pkg.rules.verdict import evaluate_differential

OWNER = {"id": "object-a", "label": "owner-only-marker", "currency": "USD", "state": "active"}
GENERIC = {"currency": "USD", "state": "active"}


def observation(status=200, body=None):
    return {"status": status, "body": body}


def evaluate(**overrides):
    params = {
        "baseline": observation(body=OWNER), "forbidden": observation(body=OWNER),
        "nonexistent": observation(404, {"error": "not found"}),
        "unauthenticated": observation(401, {"error": "authentication required"}),
        "confirm_responses": [observation(body=OWNER), observation(body=OWNER)],
    }
    params.update(overrides)
    original = copy.deepcopy(params)
    result = evaluate_differential(**params)
    assert params == original  # Deterministic, non-mutating input observations.
    for value in ("object-a", "owner-only-marker", "USD", "active"):
        assert value not in json.dumps(result)
    return result


@pytest.mark.parametrize("overrides,verdict,reason,note", [
    ({}, "FAIL", "leak_detected", None),
    ({"forbidden": observation(403)}, "PASS", None, None),
    ({"forbidden": observation(404)}, "PASS", None, None),
    ({"forbidden": observation(body={"error": "forbidden"}),
      "nonexistent": observation(body={"error": "absent"})}, "PASS", None, "soft_deny"),
    ({"baseline": observation(body=GENERIC), "forbidden": observation(body={"currency": "USD"}),
      "nonexistent": observation(body={"currency": "USD"})}, "PASS", None, "soft_deny"),
    ({"unauthenticated": observation(body=dict(reversed(list(OWNER.items()))))}, "PASS", None, "public_endpoint"),
    ({"forbidden": observation(500)}, "INCONCLUSIVE", "server_error", None),
    ({"forbidden": observation(429)}, "INCONCLUSIVE", "rate_limited", None),
    ({"forbidden": {"error": "timeout"}}, "INCONCLUSIVE", "timeout", None),
    ({"confirm_responses": [observation(403), observation(403)]}, "INCONCLUSIVE", "not_reproducible", None),
    ({"confirm_responses": []}, "INCONCLUSIVE", "not_reproducible", None),
    ({"confirm_responses": [observation(body=OWNER)]}, "INCONCLUSIVE", "not_reproducible", None),
    ({"nonexistent": observation(body=OWNER)}, "INCONCLUSIVE", "invalid_control", None),
    ({"baseline": observation(403)}, "ERROR", "baseline_not_2xx", None),
    ({"baseline": {"error": "timeout"}}, "ERROR", "baseline_timeout", None),
    ({"canaries": ["owner-only-marker"], "min_unique_leaf_values": 99}, "FAIL", "leak_detected", None),
    ({"forbidden": observation(body={"other": "unrelated"})}, "INCONCLUSIVE", "ambiguous_2xx", None),
    ({"forbidden": observation(302)}, "INCONCLUSIVE", "unexpected_status", None),
    ({"nonexistent": None, "nonexistent_skipped": True}, "INCONCLUSIVE", "ambiguous_2xx", None),
    ({"nonexistent": None, "nonexistent_skipped": True, "canaries": ["owner-only-marker"]}, "FAIL", "leak_detected", None),
    ({"nonexistent": observation(503)}, "INCONCLUSIVE", "server_error", None),
    ({"unauthenticated": observation(429)}, "INCONCLUSIVE", "rate_limited", None),
    ({"confirm_responses": [{"error": "timeout"}]}, "INCONCLUSIVE", "timeout", None),
    ({"confirm_responses": [observation(429)]}, "INCONCLUSIVE", "rate_limited", None),
    ({"confirm_responses": [observation(500)]}, "INCONCLUSIVE", "server_error", None),
], ids=["bola", "403", "404", "soft-deny", "shared-static", "public", "500", "429", "timeout",
        "non-reproducible", "no-confirms", "missing-confirm", "cached-objects", "bad-baseline",
        "baseline-timeout", "canary", "ambiguous", "redirect", "missing-control", "canary-no-control",
        "control-500", "control-429", "confirm-timeout", "confirm-429", "confirm-500"])
def test_verdict_table(overrides, verdict, reason, note):
    result = evaluate(**overrides)
    assert result["verdict"] == verdict
    assert result.get("reason") == reason
    assert result.get("note") == note
    if verdict != "PASS":
        assert isinstance(result["reason"], str)


@pytest.mark.parametrize("control,minimum,canaries", [
    (GENERIC, 2, []),
    ({"label": "owner-only-marker"}, 99, ["owner-only-marker"]),
    ({"marker": "declared-but-unobserved"}, 99, ["declared-but-unobserved"]),
    (OWNER, 2, ["owner-only-marker"]),
])
def test_invalid_control_cannot_subtract_owner_evidence(control, minimum, canaries):
    result = evaluate(nonexistent=observation(body=control), min_unique_leaf_values=minimum, canaries=canaries)
    assert (result["verdict"], result["reason"]) == ("INCONCLUSIVE", "invalid_control")
    assert result["confidence"] == "reduced"
    assert result["evidence"]["overlap_count"] == len(set(OWNER.values()))
    assert result.get("note") is None


@pytest.mark.parametrize("status", [401, 403, 404])
def test_accepted_denial_remains_pass_with_invalid_control(status):
    result = evaluate(forbidden=observation(status), nonexistent=observation(body=OWNER))
    assert result["verdict"] == "PASS"
    assert result.get("reason") is None


@pytest.mark.parametrize("canaries", [[], ["owner-only-marker"]])
def test_invalid_control_prevents_public_endpoint_pass(canaries):
    result = evaluate(nonexistent=observation(body=GENERIC), unauthenticated=observation(body=OWNER),
                      canaries=canaries)
    assert (result["verdict"], result["reason"]) == ("INCONCLUSIVE", "invalid_control")
    assert result.get("note") is None


def test_independent_owner_canary_proves_leak_despite_invalid_control():
    result = evaluate(nonexistent=observation(body=GENERIC), canaries=["owner-only-marker"])
    assert (result["verdict"], result["reason"]) == ("FAIL", "leak_detected")
    assert result["confidence"] == "reduced"
    assert result["evidence"]["canary_matched"] is True
    assert result["evidence"]["confirm_runs"] == 2
    result = evaluate(nonexistent=observation(body=GENERIC), canaries=["owner-only-marker"],
                      confirm_responses=[observation(403), observation(403)])
    assert result["reason"] == "not_reproducible"


def test_control_overlap_below_threshold_remains_usable():
    result = evaluate(baseline=observation(body=GENERIC), forbidden=observation(body=GENERIC),
                      nonexistent=observation(body=GENERIC), min_unique_leaf_values=3)
    assert result["verdict"] == "PASS"
    assert result["note"] == "soft_deny"
    assert result["evidence"]["overlap_count"] == 0


def test_ignored_control_leaves_do_not_invalidate_control():
    result = evaluate(nonexistent=observation(body={"label": "owner-only-marker"}),
                      canaries=["owner-only-marker"], min_unique_leaf_values=99, ignore_fields=["label"])
    assert result["reason"] == "ambiguous_2xx"
    assert result["evidence"]["canary_matched"] is False


def test_ignore_subtrees_and_distinct_typed_values():
    result = evaluate(baseline=observation(body={"id": 1, "timestamp": "decoration", "nested": {"request_id": "decoration"}}),
                      forbidden=observation(body={"id": True, "timestamp": "decoration", "nested": {"request_id": "decoration"}}),
                      ignore_fields=["timestamp", "nested"], nonexistent=None)
    assert result["verdict"] == "INCONCLUSIVE"
    assert result["evidence"]["overlap_count"] == 0


def test_canaries_must_come_from_owner_and_not_from_generic_control():
    result = evaluate(canaries=["absent-from-owner", "USD"], min_unique_leaf_values=99,
                      nonexistent=observation(body={"currency": "USD"}))
    assert result["verdict"] != "FAIL"
    assert result["evidence"]["canary_matched"] is False


def test_non_json_cannot_be_mistaken_for_public_null_or_soft_deny():
    result = evaluate(forbidden={"status": 200}, unauthenticated={"status": 200}, nonexistent={"status": 200})
    assert result["reason"] == "ambiguous_2xx"


def test_empty_containers_are_not_indistinguishable_response_shapes():
    result = evaluate(forbidden=observation(body={"error": []}),
                      nonexistent=observation(body={"data": {}}))
    assert result["reason"] == "ambiguous_2xx"


def test_minimum_is_unique_values_not_repeated_leaves():
    result = evaluate(baseline=observation(body={"a": "one", "b": "one"}),
                      forbidden=observation(body={"a": "one", "b": "one"}),
                      nonexistent=observation(404, {"message": "absent"}))
    assert result["evidence"]["overlap_count"] == 1
    assert result["verdict"] != "FAIL"


def test_confirmations_need_stable_owner_specific_evidence():
    result = evaluate(confirm_responses=[observation(body={"id": "object-a", "label": "owner-only-marker"}),
                                            observation(body={"currency": "USD", "state": "active"})])
    assert result["reason"] == "not_reproducible"


def test_confirmations_that_drop_private_values_do_not_confirm_static_overlap():
    result = evaluate(confirm_responses=[observation(body=GENERIC), observation(body=GENERIC)])
    assert result["reason"] == "not_reproducible"


def test_explicit_zero_confirms_and_reduced_confidence():
    result = evaluate(confirm=0, confirm_responses=[], nonexistent=None, canaries=["owner-only-marker"],
                      nonexistent_skipped=True)
    assert result["verdict"] == "FAIL"
    assert result["confidence"] == "reduced"
    assert result["evidence"]["nonexistent_skipped"] is True
