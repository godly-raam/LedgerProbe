"""JSON logs, Prometheus text metrics, and GitHub Action summaries."""
from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .auth import redact
from .fingerprints import result_fingerprint

REQUIRED = ("ts", "level", "event", "run_id", "rule_id", "fingerprint", "verdict",
            "reason", "duration_ms", "http_status", "target", "tool_version")


def log_event(run_id, event, *, target, tool_version, result=None, stream=None,
              duration_ms=0, http_status=None, level="info", extra=None):
    result = result or {}
    record = {
        "ts": datetime.now(timezone.utc).isoformat(), "level": level, "event": event,
        "run_id": redact(run_id), "rule_id": redact(result.get("rule_id", "")),
        "fingerprint": result_fingerprint(result) if result else "",
        "verdict": result.get("verdict", ""), "reason": redact(result.get("reason", "")),
        "duration_ms": float(duration_ms), "http_status": http_status,
        "target": redact(target), "tool_version": tool_version,
        "path_template": redact(result.get("path_template", result.get("path", ""))),
    }
    if extra:
        record.update({key: redact(value) for key, value in extra.items()})
    (stream or sys.stdout).write(json.dumps(record, sort_keys=True) + "\n")
    return record


def metrics_text(results, *, duration_seconds, tracker_errors=0, auth_errors=0):
    verdicts = Counter(result.get("verdict", "UNKNOWN") for result in results)
    inconclusive = sum(result.get("status") == "inconclusive" for result in results)
    lines = ["# HELP ledgerprobe_verdict_count Findings by verdict.",
             "# TYPE ledgerprobe_verdict_count gauge"]
    for verdict, count in sorted(verdicts.items()):
        lines.append(f'ledgerprobe_verdict_count{{verdict="{verdict}"}} {count}')
    lines += ["# HELP ledgerprobe_inconclusive_ratio Ratio of inconclusive checks.",
              "# TYPE ledgerprobe_inconclusive_ratio gauge",
              f"ledgerprobe_inconclusive_ratio {inconclusive / max(1, len(results))}",
              f"ledgerprobe_run_duration_seconds {float(duration_seconds)}",
              f"ledgerprobe_tracker_errors_total {int(tracker_errors)}",
              f"ledgerprobe_auth_errors_total {int(auth_errors)}"]
    return "\n".join(lines) + "\n"


def write_metrics(path, text):
    Path(path).write_text(text, encoding="utf-8")


def github_summary(document):
    summary = document.get("summary", {})
    lines = ["## LedgerProbe", "",
             f"Checks: **{summary.get('checks', 0)}** · Passed **{summary.get('passed', 0)}** · "
             f"Failed **{summary.get('failed', 0)}** · Inconclusive **{summary.get('inconclusive', 0)}**",
             "", "| Rule | Fingerprint | Status |", "| --- | --- | --- |"]
    for finding in document.get("findings", []):
        lines.append(f"| `{finding.get('rule_id', '')}` | `{finding.get('fingerprint', '')}` | {finding.get('status', '')} |")
    return "\n".join(lines) + "\n"
