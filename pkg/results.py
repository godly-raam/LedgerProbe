"""Versioned JSON results, baseline classification, and diff documents."""
from __future__ import annotations

import copy
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .cvss import DEFAULT_VECTORS, rating
from .fingerprints import result_fingerprint
from .reporter._evidence import result_properties
from .version import __version__

SCHEMA_VERSION = "ledgerprobe-results/1"
TOOL_VERSION = __version__
_STATUSES = {"passed", "failed", "inconclusive", "skipped", "error", "suppressed"}


def _cvss(result: dict) -> dict:
    value = result.get("cvss")
    if isinstance(value, dict) and isinstance(value.get("vector"), str):
        output = {"vector": value["vector"], "score": value["score"],
                  "rating": value.get("rating", rating(value["score"]))}
        if isinstance(value.get("justification"), str):
            output["justification"] = value["justification"]
        return output
    score = result.get("cvss_score", 0.0)
    vector = DEFAULT_VECTORS.get(result.get("check_type", "bola"), DEFAULT_VECTORS["bola"])
    return {"vector": vector, "score": score, "rating": rating(float(score))}


def _record(result: dict, *, status: str | None = None) -> dict:
    properties = result_properties(result)
    record = {
        "fingerprint": result_fingerprint(result),
        "rule_id": result.get("rule_id", "unknown"),
        "method": result.get("method", "GET"),
        "path_template": result.get("path_template", result.get("path", "")),
        "check_type": result.get("check_type", "bola"),
        "verdict": result.get("verdict", {
            "failed": "FAIL", "suppressed": "FAIL", "passed": "PASS",
            "inconclusive": "INCONCLUSIVE", "skipped": "SKIPPED", "error": "ERROR",
        }.get(status or result.get("status"), "INCONCLUSIVE")),
    }
    status = status or result.get("status")
    if status:
        record["status"] = status
    for key in ("reason", "confidence", "severity"):
        if result.get(key) is not None:
            record[key] = result[key]
    if result.get("cwe") is not None:
        record["cwe"] = result["cwe"]
    if result.get("note") is not None:
        record["notes"] = [result["note"]]
    if status in {"failed", "suppressed"}:
        record["cvss"] = _cvss(result)
        record["evidence"] = properties.get("evidence", {})
        if status == "suppressed":
            suppression = result.get("suppression") or {}
            record["suppression"] = {
                key: suppression[key] for key in ("owner", "reason", "expires")
                if isinstance(suppression.get(key), str)
            }
    if result.get("baseline_status") in {"new", "unchanged", "resolved", "unverified"}:
        record["baseline_status"] = result["baseline_status"]
    return record


def _warning(value) -> dict:
    return {key: value[key] for key in ("code", "owner", "expires", "fingerprint", "rule_id")
            if isinstance(value.get(key), str) and value[key]}


def build_document(results, *, target: str, modes: dict, warnings=(), baseline=None,
                   suppressions=None, timestamp=None, drift=None) -> dict:
    results = list(results)
    counts = Counter(result.get("status") for result in results)
    for key in _STATUSES:
        counts.setdefault(key, 0)
    findings = [_record(result) for result in results
                if result.get("status") in {"failed", "suppressed"}]
    skipped = [_record(result) for result in results if result.get("status") == "skipped"]
    errors = [_record(result) for result in results if result.get("status") == "error"]
    document = {
        "schema_version": SCHEMA_VERSION,
        "run": {
            "tool": "LedgerProbe",
            "tool_version": TOOL_VERSION,
            "timestamp": timestamp or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "target": target,
            "modes": {
                "read_only": bool(modes.get("read_only", False)),
                "allow_mutations": bool(modes.get("allow_mutations", False)),
                "spec_check": modes.get("spec_check", "strict"),
                "sync_modes": sorted({result.get("evidence", {}).get("sync_mode")
                                      for result in results
                                      if result.get("evidence", {}).get("sync_mode")}),
            },
        },
        "summary": {
            "checks": len(results),
            "passed": counts["passed"], "failed": counts["failed"],
            "inconclusive": counts["inconclusive"], "skipped": counts["skipped"],
            "error": counts["error"], "suppressed": counts["suppressed"],
            "findings": len(findings),
        },
        "findings": findings,
        "skipped": skipped,
        "errors": errors,
        "warnings": [_warning(item) for item in warnings if isinstance(item, dict) and item.get("code")],
    }
    if baseline is not None:
        document["summary"].update({key: baseline.get(key, 0)
                                    for key in ("new", "unchanged", "resolved", "unverified")})
        document["baseline"] = {
            "new": baseline.get("new", 0),
            "unchanged": baseline.get("unchanged", 0),
            "resolved": baseline.get("resolved", 0),
            "unverified": baseline.get("unverified", 0),
        }
    if suppressions is not None:
        document["summary"].update({
            "suppressions_active": suppressions.get("active", 0),
            "suppressions_expired": suppressions.get("expired", 0),
            "stale_suppressions": suppressions.get("stale", 0),
        })
    if drift is not None:
        document["drift"] = drift
    return document


def write_document(document: dict, path) -> Path:
    path = Path(path)
    path.write_text(json.dumps(document, indent=2, ensure_ascii=True, allow_nan=False) + "\n",
                    encoding="utf-8")
    return path


def load_document(path) -> dict:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ValueError("results JSON could not be read") from None
    if not isinstance(document, dict) or document.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("results JSON schema mismatch; expected " + SCHEMA_VERSION)
    if not isinstance(document.get("findings"), list):
        raise ValueError("results JSON schema mismatch; findings must be a list")
    return document


def baseline_document(path) -> dict:
    return load_document(path)


def _prior_failures(document: dict) -> dict:
    """Return fingerprint -> rule_id for unsuppressed FAIL findings only."""
    prior = {}
    for finding in document.get("findings", []):
        if not isinstance(finding, dict) or not isinstance(finding.get("fingerprint"), str):
            continue
        if finding.get("verdict") not in {None, "FAIL"} or finding.get("status") == "suppressed":
            continue
        prior[finding["fingerprint"]] = finding.get("rule_id")
    return prior


def _classify(prior: dict, current: list[dict]) -> tuple[list[str | None], dict[str, list[dict]]]:
    """Shared baseline classification for apply_baseline and diff_documents."""
    statuses: list[str | None] = []
    rows = {"new": [], "unchanged": [], "resolved": [], "unverified": []}
    observed = set()
    for item in current:
        fingerprint = item["fingerprint"]
        observed.add(fingerprint)
        verdict = item.get("verdict") or "FAIL"
        suppressed = item.get("status") == "suppressed"
        if verdict == "FAIL" and not suppressed:
            status = "unchanged" if fingerprint in prior else "new"
        elif verdict == "FAIL" and suppressed and fingerprint in prior:
            status = "unchanged"
        elif verdict == "PASS" and fingerprint in prior:
            status = "resolved"
        elif fingerprint in prior:
            status = "unverified"
        else:
            status = None
        statuses.append(status)
        if status:
            rows[status].append({"fingerprint": fingerprint,
                                 "rule_id": item.get("rule_id") or prior.get(fingerprint)})
    for fingerprint, rule_id in prior.items():
        if fingerprint not in observed:
            rows["unverified"].append({"fingerprint": fingerprint, "rule_id": rule_id})
    for key in rows:
        rows[key].sort(key=lambda row: row["fingerprint"])
    return statuses, rows


def apply_baseline(results, document: dict):
    prior = _prior_failures(document)
    results = list(results)
    current = []
    for result in results:
        copied = copy.deepcopy(result)
        current.append({"fingerprint": result_fingerprint(copied),
                        "rule_id": copied.get("rule_id"),
                        "verdict": copied.get("verdict"),
                        "status": copied.get("status"), "result": copied})
    statuses, rows = _classify(prior, current)
    output = []
    for item, status in zip(current, statuses):
        copied = item["result"]
        if status:
            copied["baseline_status"] = status
        output.append(copied)
    return output, {key: len(rows[key]) for key in ("new", "unchanged", "resolved", "unverified")}


def diff_documents(old: dict, new: dict) -> dict:
    prior = _prior_failures(old)
    current = []
    for item in new.get("findings", []) + new.get("skipped", []) + new.get("errors", []):
        if isinstance(item, dict) and isinstance(item.get("fingerprint"), str):
            current.append(item)
    _, rows = _classify(prior, current)
    return rows


def gate_exit(results, *, fail_on="any", fail_on_inconclusive=False,
              fail_on_stale=False, stale=0) -> int:
    """Apply the documented scan exit policy to already-filtered results."""
    counts = Counter(result.get("status") for result in results)
    if counts["error"] or not (counts["passed"] + counts["failed"]
                               + counts["inconclusive"] + counts["suppressed"]):
        return 2
    if fail_on == "new":
        finding_failure = any(result.get("status") == "failed"
                              and result.get("baseline_status") == "new" for result in results)
    elif fail_on == "none":
        finding_failure = False
    else:
        finding_failure = counts["failed"] > 0
    if finding_failure or (fail_on_inconclusive and counts["inconclusive"]):
        return 1
    if fail_on_stale and stale:
        return 1
    return 0
