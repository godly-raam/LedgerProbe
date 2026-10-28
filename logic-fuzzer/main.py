from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path

from fuzzer.api import BankAPI
from fuzzer.report import build_report, utcnow, write_report
from fuzzer.suites import run_bola, run_mcc, run_race

SUITES = {"bola": run_bola, "mcc": run_mcc, "race": run_race}


async def execute(args: argparse.Namespace) -> int:
    selected = [suite.strip() for suite in args.suites.split(",") if suite.strip()]
    unknown = [suite for suite in selected if suite not in SUITES]
    if not selected or unknown:
        print(f"error: unknown suites {unknown or selected}; choose from {list(SUITES)}")
        return 2

    api = BankAPI(args.base_url, timeout=args.timeout)
    started_at = utcnow()
    findings: list[dict] = []
    checks: list[dict] = []
    graph = {"nodes": [], "edges": []}

    try:
        for suite in selected:
            print(f"[*] running {suite} suite against {args.base_url}")
            try:
                result = await SUITES[suite](api)
            except Exception as exc:  # keep other suites running, surface the failure
                print(f"[!] {suite} suite failed: {exc}")
                return 1
            findings.extend(result["findings"])
            checks.extend(result["checks"])
            for node in result["graph"]["nodes"]:
                if node not in graph["nodes"]:
                    graph["nodes"].append(node)
            graph["edges"].extend(result["graph"]["edges"])
    finally:
        await api.close()

    finished_at = utcnow()
    report = build_report(
        target=args.base_url,
        started_at=started_at,
        finished_at=finished_at,
        findings=findings,
        checks=checks,
        graph=graph,
    )
    path = write_report(args.out, report)

    run = report["run"]
    print()
    print(f"[+] {run['id']}  score {run['score']}/100 (grade {run['grade']})")
    print(f"    {run['checks_passed']}/{run['checks_total']} checks passed")
    for finding in report["findings"]:
        print(
            f"    {finding['id']}  {finding['severity'].upper():<8} "
            f"CVSS {finding['cvss']['score']:<4} {finding['title']}"
        )
    print(f"[+] report written to {path}")
    return 0 if report["findings"] else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="FinShield-Core authorization and race-condition fuzzer")
    parser.add_argument(
        "--base-url",
        default=os.environ.get("FINSHIELD_TARGET", "http://127.0.0.1:8000"),
        help="mock bank base URL",
    )
    parser.add_argument("--out", default=str(Path(__file__).parent / "reports"), help="report output directory")
    parser.add_argument("--suites", default="bola,mcc,race", help="comma-separated suites: bola,mcc,race")
    parser.add_argument("--timeout", type=float, default=15.0, help="per-request timeout in seconds")
    return asyncio.run(execute(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
