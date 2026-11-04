"""DefectDojo Generic Findings Import export and experimental upload."""
from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .auth import SecretResolver
from .cwe import cwe_for
from .fingerprints import result_fingerprint


def _severity(result):
    rating = (result.get("cvss") or {}).get("rating")
    if not rating:
        score = float(result.get("cvss_score", 0) or 0)
        rating = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score else "info"
    return str(rating).capitalize()


def build_export(results, *, target, when=None):
    host = target.split("://", 1)[-1].split("/", 1)[0]
    day = (when or datetime.now(timezone.utc)).date().isoformat()
    output = []
    for result in results:
        if result.get("status") not in {"failed", "suppressed"}:
            continue
        check = result.get("check_type", "bola")
        output.append({
            "title": result.get("name") or result.get("rule_id", "LedgerProbe finding"),
            "description": str(result.get("message") or result.get("name") or "LedgerProbe finding"),
            "severity": _severity(result),
            "mitigation": result.get("remediation") or "Review the authorization rule and apply the documented remediation.",
            "date": day,
            "cvssv3": (result.get("cvss") or {}).get("vector", ""),
            "cwe": int(result.get("cwe") or cwe_for(check, result.get("reason"))),
            "unique_id_from_tool": result_fingerprint(result),
            "vuln_id_from_tool": result.get("rule_id", "unknown"),
            "component_name": host,
            "endpoints": [result.get("path_template") or result.get("path", "")],
            "active": result.get("status") != "suppressed",
            "false_p": result.get("status") == "suppressed",
        })
    return output


def write_export(results, path, *, target):
    path = Path(path)
    path.write_text(json.dumps(build_export(results, target=target), indent=2) + "\n", encoding="utf-8")
    return path


async def upload(client, results, *, endpoint, token_ref, engagement, product,
                 close_old_findings=False, target, transport=None):
    token = await SecretResolver(transport=transport).resolve(token_ref)
    payload = build_export(results, target=target)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(payload, handle)
        name = handle.name
    try:
        with open(name, "rb") as handle:
            return await client.request(
                "POST", endpoint.rstrip("/") + "/api/v2/import-scan/",
                headers={"Authorization": "Token " + token.reveal()},
                data={"scan_type": "Generic Findings Import", "engagement": engagement,
                      "product_name": product,
                      "close_old_findings": str(close_old_findings).lower()},
                files={"file": ("findings.json", handle, "application/json")},
            )
    finally:
        Path(name).unlink(missing_ok=True)
