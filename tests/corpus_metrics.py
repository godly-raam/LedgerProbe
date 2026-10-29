"""Compute precision, recall, and confusion matrix metrics across the authorization fixture corpus."""
from __future__ import annotations

import argparse
import asyncio
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.fixtures.authz_server import load_expectations
from tests.test_corpus import execute_profile


def run_metrics(output_path: Path | None = None) -> int:
    """Run all profiles, compute metrics, print/save markdown report, and return exit code."""
    expectations = load_expectations()
    results = []

    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        for profile_name, spec in expectations.items():
            run_tmp = tmp_dir / profile_name
            run_tmp.mkdir(parents=True, exist_ok=True)
            _, result, _, _ = asyncio.run(execute_profile(profile_name, run_tmp))

            verdict = result["verdict"]
            reason = result.get("reason")
            note = result.get("note")

            expected_verdict = spec["expected_verdict"]
            expected_reason = spec["expected_reason"]
            expected_note = spec["expected_note"]

            matched = (
                verdict == expected_verdict
                and reason == expected_reason
                and note == expected_note
            )

            results.append({
                "profile": profile_name,
                "category": spec["category"],
                "description": spec.get("description", ""),
                "expected_verdict": expected_verdict,
                "expected_reason": expected_reason,
                "expected_note": expected_note,
                "actual_verdict": verdict,
                "actual_reason": reason,
                "actual_note": note,
                "matched": matched,
            })

    # Confusion matrix metrics
    tp = sum(1 for r in results if r["category"] == "vulnerable" and r["actual_verdict"] == "FAIL")
    fn = sum(1 for r in results if r["category"] == "vulnerable" and r["actual_verdict"] != "FAIL")
    tn = sum(1 for r in results if r["category"] == "safe" and r["actual_verdict"] == "PASS")
    fp = sum(1 for r in results if r["category"] == "safe" and r["actual_verdict"] == "FAIL")

    safe_unexpected = sum(
        1 for r in results if r["category"] == "safe" and r["actual_verdict"] not in ("PASS", "FAIL")
    )

    tricky_total = sum(1 for r in results if r["category"] == "tricky")
    tricky_matched = sum(1 for r in results if r["category"] == "tricky" and r["matched"])
    tricky_failed = tricky_total - tricky_matched

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0

    ci_passed = (fn == 0 and fp == 0 and safe_unexpected == 0 and tricky_failed == 0)

    # Format Markdown
    lines = [
        "# LedgerProbe Authorization Fixture Corpus Benchmark",
        "",
        "## Profile Registry & Evaluation Results",
        "",
        "| Profile | Category | Expected | Actual | Match |",
        "| --- | --- | --- | --- | :---: |",
    ]

    for r in results:
        exp_detail = r["expected_reason"] or (f"note:{r['expected_note']}" if r["expected_note"] else "-")
        act_detail = r["actual_reason"] or (f"note:{r['actual_note']}" if r["actual_note"] else "-")
        exp_str = f"**{r['expected_verdict']}** ({exp_detail})"
        act_str = f"**{r['actual_verdict']}** ({act_detail})"
        status_icon = "PASS" if r["matched"] else "FAIL"
        lines.append(f"| `{r['profile']}` | {r['category']} | {exp_str} | {act_str} | {status_icon} |")

    lines.extend([
        "",
        "## Metrics Summary",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| **True Positives (TP)** | {tp} |",
        f"| **True Negatives (TN)** | {tn} |",
        f"| **False Positives (FP)** | {fp} |",
        f"| **False Negatives (FN)** | {fn} |",
        f"| **Tricky Profile Matches** | {tricky_matched}/{tricky_total} |",
        f"| **Total Profiles Tested** | {len(results)} |",
        f"| **Precision** | {precision * 100:.1f}% ({precision:.4f}) |",
        f"| **Recall** | {recall * 100:.1f}% ({recall:.4f}) |",
        f"| **CI Benchmark Gate** | {'PASSED' if ci_passed else 'FAILED'} |",
        "",
    ])

    report = "\n".join(lines)
    print(report)

    if output_path is not None:
        output_path.write_text(report, encoding="utf-8")
        print(f"\n[+] Metrics report written to: {output_path}")

    return 0 if ci_passed else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="LedgerProbe Authorization Corpus Metrics Runner")
    parser.add_argument("--output", "-o", type=Path, help="Path to write the markdown metrics report")
    args = parser.parse_args(argv)
    return run_metrics(args.output)


if __name__ == "__main__":
    sys.exit(main())
