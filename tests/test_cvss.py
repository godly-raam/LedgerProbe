from __future__ import annotations

import pytest

from pkg.cvss import (
    DEFAULT_VECTORS, parse_vector, rating, resolve_cvss, score_vector,
)


REFERENCE = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5, "medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "none"),
    # The official CVSS 3.1 score is 1.8; the request's 1.6 is not this vector.
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8, "low"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, "critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1, "critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N", 7.7, "high"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 8.8, "high"),
    ("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H", 8.0, "high"),
]


@pytest.mark.parametrize("vector,expected,expected_rating", REFERENCE)
def test_reference_vectors(vector, expected, expected_rating):
    result = score_vector(vector)
    assert result["score"] == expected
    assert result["rating"] == expected_rating
    assert rating(expected) == expected_rating


@pytest.mark.parametrize("vector", [
    "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/X:N",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:N",
    "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/",
    "",
    None,
])
def test_malformed_vectors_rejected(vector):
    with pytest.raises(ValueError):
        parse_vector(vector)


def test_default_vectors_are_valid_and_scoped():
    assert set(DEFAULT_VECTORS) == {
        "bola", "state_change", "race", "unauthenticated_access",
        "caller_scope", "shared_scope", "bfla", "mass_assignment", "business_limit",
    }
    for vector in DEFAULT_VECTORS.values():
        assert 0 <= score_vector(vector)["score"] <= 10
    assert score_vector(DEFAULT_VECTORS["unauthenticated_access"])["score"] == 7.5


def test_rule_override_requires_a_justification_and_is_used():
    rule = {"cvss_score": 8.1, "cvss": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "justification": "Internet-facing, pre-auth data destruction.",
    }}
    result = resolve_cvss(rule, "bola")
    assert result["score"] == 9.8
    assert result["rating"] == "critical"
    assert result["justification"].startswith("Internet-facing")
    for bad in (
        {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "justification": " "},
        {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         "justification": "valid", "extra": "no"},
    ):
        with pytest.raises(ValueError):
            resolve_cvss({"cvss": bad}, "bola")
