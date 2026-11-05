"""CWE classification shared by JSON, SARIF, and DefectDojo exports."""
from __future__ import annotations

CWE_BY_CHECK = {
    "bola": 639,
    "state_change": 639,
    "unauthenticated_access": 306,
    "caller_scope": 639,
    "shared_scope": 639,
    "race": 362,
    "bfla": 285,
    "mass_assignment": 915,
    "business_limit": 840,
}


def cwe_for(check_type: str, reason: str | None = None) -> int:
    if reason == "unauthenticated_leak":
        return 306
    return CWE_BY_CHECK.get(check_type, 639)
