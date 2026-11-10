"""SARIF 2.1.0 output for API checks (endpoints are not source files)."""

import json
from pathlib import Path

from ._evidence import _REASONS, result_properties
from ..fingerprints import result_fingerprint


_LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def write_sarif(results, path, *, source_uri=None, warnings=()) -> Path:
    """Write failed checks as findings and execution errors as notifications.

    Pass the tracked local spec's repository-relative URI as ``source_uri`` to
    link findings to source. The caller selects the spec; no regions are inferred.
    Without it, locations describe only the logical API endpoints.
    """
    rules, indexes, findings, notifications = [], {}, [], []
    for warning in warnings:
        if isinstance(warning, dict) and warning.get("code"):
            notifications.append({"level": "warning", "message": {"text": warning["code"]},
                                  "properties": {key: value for key, value in warning.items()
                                                 if key in {"code", "owner", "expires", "fingerprint", "rule_id"}}})
    execution_failed = False
    for result in results:
        if result.get("spec_drift"):
            notifications.append({
                "level": "warning",
                "message": {"text": f"spec_drift: {result['spec_drift']} is absent from the spec"},
                "properties": {"spec_drift": result["spec_drift"]},
            })
        rule_id = result["rule_id"]
        if rule_id not in indexes:
            indexes[rule_id] = len(rules)
            rules.append({
                "id": rule_id,
                "name": result["name"],
                "shortDescription": {"text": result["name"]},
                "defaultConfiguration": {"level": _LEVELS[result["severity"]]},
                "properties": {
                    "security-severity": str(result.get("cvss", {}).get("score", result["cvss_score"])),
                    "cwe": result.get("cwe"),
                    "tags": ["security", "owasp", "owasp/" + result["owasp_category"]],
                },
            })
        if result["status"] == "inconclusive":
            inconclusive_location: dict[str, object] = {"logicalLocations": [{
                "fullyQualifiedName": result["method"] + " " + result["path"],
            }]}
            if source_uri is not None:
                inconclusive_location["physicalLocation"] = {"artifactLocation": {"uri": str(source_uri)}}
            findings.append({
                "level": "note",
                "ruleId": rule_id,
                "ruleIndex": indexes[rule_id],
                "message": {"text": result.get("message") or result["name"]},
                "locations": [inconclusive_location],
                "partialFingerprints": {
                    "ledgerprobe/v1": result_fingerprint(result),
                },
                "kind": "review",
                "properties": {"status": "inconclusive", "tags": ["inconclusive"], **result_properties(result)},
            })
            continue
        reference = {"id": rule_id, "index": indexes[rule_id]}
        if result["status"] == "error":
            execution_failed = True
            notification = {
                "associatedRule": reference,
                "level": "error",
                "message": {"text": result["message"] or "Check execution failed."},
            }
            if properties := result_properties(result):
                notification["properties"] = properties
            notifications.append(notification)
        elif result["status"] in {"failed", "suppressed"}:
            location: dict[str, object] = {"logicalLocations": [{
                "fullyQualifiedName": result["method"] + " " + result["path"],
            }]}
            if source_uri is not None:
                location["physicalLocation"] = {"artifactLocation": {"uri": str(source_uri)}}
            finding = {
                "ruleId": rule_id,
                "ruleIndex": indexes[rule_id],
                "level": _LEVELS[result["severity"]],
                "message": {"text": result.get("message") or result["name"]},
                "locations": [location],
                "partialFingerprints": {
                    "ledgerprobe/v1": result_fingerprint(result),
                },
            }
            if result.get("cwe"):
                finding["taxa"] = [{"id": str(result["cwe"]), "name": f"CWE-{result['cwe']}"}]
                finding.setdefault("properties", {})["cwe"] = result["cwe"]
            if result.get("status") == "suppressed" and isinstance(result.get("suppression"), dict):
                finding["suppressions"] = [{
                    "kind": "external",
                    "justification": result["suppression"].get("reason", "external suppression"),
                }]
            if properties := result_properties(result):
                finding["properties"] = properties
            findings.append(finding)
        elif result["status"] == "skipped" and result.get("reason") in _REASONS:
            notifications.append({
                "associatedRule": reference,
                "level": "note",
                "message": {"text": result.get("message") or result["name"]},
                "properties": result_properties(result),
            })
    report = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "LedgerProbe", "rules": rules}},
            "invocations": [{
                "executionSuccessful": not execution_failed,
                "toolExecutionNotifications": notifications,
            }],
            "results": findings,
        }],
    }
    path = Path(path)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False) + "\n", encoding="utf-8")
    return path
