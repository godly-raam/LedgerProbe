from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 7, "low": 3}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITIES = ("critical", "high", "medium", "low")


def _grade(score: int) -> str:
    for floor, grade in ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (40, "E")):
        if score >= floor:
            return grade
    return "F"


def build_report(
    target: str,
    started_at: datetime,
    finished_at: datetime,
    findings: list[dict],
    checks: list[dict],
    graph: dict,
) -> dict:
    deduped: dict[str, dict] = {}
    for finding in findings:
        deduped.setdefault(finding["check_id"], finding)
    ordered = sorted(
        deduped.values(),
        key=lambda item: (-item["cvss"]["score"], SEVERITY_ORDER[item["severity"]]),
    )

    findings_by_check: dict[str, str] = {}
    for index, finding in enumerate(ordered, start=1):
        finding["id"] = f"FS-{index:03d}"
        findings_by_check[finding["check_id"]] = finding["id"]

    for edge in graph.get("edges", []):
        edge["finding_id"] = findings_by_check.get(edge.get("check_id"))

    severity_counts = Counter(finding["severity"] for finding in ordered)
    deductions = sum(SEVERITY_WEIGHT[finding["severity"]] for finding in ordered)
    score = max(0, 100 - deductions)

    owasp_counts: Counter = Counter()
    owasp_names: dict[str, str] = {}
    endpoint_groups: dict[str, list[dict]] = {}
    for finding in ordered:
        owasp_counts[finding["owasp"]["id"]] += 1
        owasp_names[finding["owasp"]["id"]] = finding["owasp"]["name"]
        endpoint_groups.setdefault(finding["endpoint"], []).append(finding)

    endpoints = []
    for endpoint, group in endpoint_groups.items():
        worst = max(group, key=lambda item: item["cvss"]["score"])
        endpoints.append(
            {
                "endpoint": endpoint,
                "findings": len(group),
                "max_cvss": worst["cvss"]["score"],
                "worst_severity": worst["severity"],
                "owasp": sorted({item["owasp"]["id"] for item in group}),
            }
        )
    endpoints.sort(key=lambda item: (-item["max_cvss"], item["endpoint"]))

    passed = sum(1 for check in checks if check["passed"])
    return {
        "schema_version": "1.0",
        "run": {
            "id": started_at.strftime("FSR-%Y%m%d-%H%M%S"),
            "target": target,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_ms": round((finished_at - started_at).total_seconds() * 1000),
            "score": score,
            "grade": _grade(score),
            "checks_total": len(checks),
            "checks_passed": passed,
            "checks_failed": len(checks) - passed,
        },
        "summary": {
            "findings": len(ordered),
            "by_severity": {severity: severity_counts.get(severity, 0) for severity in SEVERITIES},
            "by_owasp": [
                {"id": oid, "name": owasp_names[oid], "count": count}
                for oid, count in sorted(owasp_counts.items())
            ],
            "endpoints": endpoints,
        },
        "findings": ordered,
        "graph": graph,
        "checks": checks,
    }


def write_report(out_dir: str | Path, report: dict) -> Path:
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"report-{report['run']['id']}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
