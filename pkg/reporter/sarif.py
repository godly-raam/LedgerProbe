"""SARIF 2.1.0 output for API checks (endpoints are not source files)."""

import hashlib
import json
from pathlib import Path


_LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def write_sarif(results, path, *, source_uri=None) -> Path:
    """Write failed checks as findings and execution errors as notifications.

    Pass the tracked local spec's repository-relative URI as ``source_uri`` to
    link findings to source. The caller selects the spec; no regions are inferred.
    Without it, locations describe only the logical API endpoints.
    """
    rules, indexes, findings, notifications = [], {}, [], []
    for result in results:
        rule_id = result["rule_id"]
        if rule_id not in indexes:
            indexes[rule_id] = len(rules)
            rules.append({
                "id": rule_id,
                "name": result["name"],
                "shortDescription": {"text": result["name"]},
                "defaultConfiguration": {"level": _LEVELS[result["severity"]]},
                "properties": {
                    "security-severity": str(result["cvss_score"]),
                    "tags": ["security", "owasp", "owasp/" + result["owasp_category"]],
                },
            })
        reference = {"id": rule_id, "index": indexes[rule_id]}
        if result["status"] == "error":
            notifications.append({
                "associatedRule": reference,
                "level": "error",
                "message": {"text": result["message"] or "Check execution failed."},
            })
        elif result["status"] == "failed":
            identity = json.dumps([rule_id, result["method"], result["path"]], ensure_ascii=True)
            location: dict[str, object] = {"logicalLocations": [{
                "fullyQualifiedName": result["method"] + " " + result["path"],
            }]}
            if source_uri is not None:
                location["physicalLocation"] = {"artifactLocation": {"uri": str(source_uri)}}
            findings.append({
                "ruleId": rule_id,
                "ruleIndex": indexes[rule_id],
                "level": _LEVELS[result["severity"]],
                "message": {"text": result["message"] or result["name"]},
                "locations": [location],
                "partialFingerprints": {
                    "ledgerprobe/v1": hashlib.sha256(identity.encode("utf-8")).hexdigest(),
                },
            })
    report = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "LedgerProbe", "rules": rules}},
            "invocations": [{
                "executionSuccessful": not notifications,
                "toolExecutionNotifications": notifications,
            }],
            "results": findings,
        }],
    }
    path = Path(path)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False) + "\n", encoding="utf-8")
    return path
