"""CVSS v3.1 base scoring with strict, dependency-free vector parsing."""
from __future__ import annotations

import math

PREFIX = "CVSS:3.1/"
_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_VALUES = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "R"},
    "S": {"U", "C"},
    "C": {"H", "L", "N"},
    "I": {"H", "L", "N"},
    "A": {"H", "L", "N"},
}
_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"U": {"N": 0.85, "L": 0.62, "H": 0.27},
           "C": {"N": 0.85, "L": 0.68, "H": 0.50}},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

# Defaults are deliberately attributable to a check's exploit model, not to a
# historical score. Rule-level `cvss:` overrides are available when a policy has
# better environmental knowledge.
DEFAULT_VECTORS = {
    "bola": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "state_change": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "race": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
    "caller_scope": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
    "shared_scope": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
    "unauthenticated_access": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "bfla": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "mass_assignment": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "business_limit": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
}


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A Roundup, using integer arithmetic."""
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    if not isinstance(vector, str) or not vector.startswith(PREFIX):
        raise ValueError("CVSS vector must use the CVSS:3.1/ prefix")
    parts = vector[len(PREFIX):].split("/")
    parsed: dict[str, str] = {}
    for part in parts:
        key, separator, value = part.partition(":")
        if not separator or key not in _VALUES or value not in _VALUES[key]:
            raise ValueError("CVSS vector contains an invalid or unknown metric")
        if key in parsed:
            raise ValueError("CVSS vector contains a duplicate metric")
        parsed[key] = value
    missing = [key for key in _ORDER if key not in parsed]
    if missing:
        raise ValueError("CVSS vector is missing a base metric")
    return parsed


def score_vector(vector: str) -> dict:
    metrics = parse_vector(vector)
    scope = metrics["S"]
    iss = 1.0 - ((1.0 - _WEIGHTS["C"][metrics["C"]])
                 * (1.0 - _WEIGHTS["I"][metrics["I"]])
                 * (1.0 - _WEIGHTS["A"][metrics["A"]]))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = (8.22 * _WEIGHTS["AV"][metrics["AV"]]
                      * _WEIGHTS["AC"][metrics["AC"]]
                      * _WEIGHTS["PR"][scope][metrics["PR"]]
                      * _WEIGHTS["UI"][metrics["UI"]])
    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = _roundup(min(impact + exploitability, 10.0))
    else:
        score = _roundup(min(1.08 * (impact + exploitability), 10.0))
    return {"vector": vector, "score": score, "rating": rating(score)}


def rating(score: float) -> str:
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def resolve_cvss(rule: dict, check_type: str) -> dict:
    override = rule.get("cvss")
    if override is None:
        vector = DEFAULT_VECTORS[check_type]
        return score_vector(vector)
    if not isinstance(override, dict) or set(override) != {"vector", "justification"}:
        raise ValueError("cvss override requires vector and justification")
    vector = override["vector"]
    if not isinstance(override["justification"], str) or not override["justification"].strip():
        raise ValueError("cvss override requires a nonempty justification")
    result = score_vector(vector)
    result["justification"] = override["justification"]
    return result
