"""DefectDojo Generic Findings Import export and experimental upload."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path

from .auth import redact
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
            "title": "LedgerProbe: " + redact(str(result.get("rule_id", "finding"))),
            "description": redact("LedgerProbe finding on " + str(result.get("method", "GET")) + " "
                                  + str(result.get("path_template") or result.get("path", "/"))
                                  + "; evidence values are redacted."),
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
    payload = build_export(results, target=target)
    try:
        import jsonschema
        schema_path = files("schemas").joinpath("defectdojo.generic.schema.json")
        jsonschema.Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8"))).validate(payload)
    except ImportError:
        pass  # jsonschema is a development-only validation dependency
    path = Path(path)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True, allow_nan=False) + "\n", encoding="utf-8")
    return path
