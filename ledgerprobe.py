"""Spec-driven security checks, independent of the bundled banking lab."""
from __future__ import annotations

import argparse
import asyncio
import builtins
import json
import math
import os
import secrets
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import quote, urlsplit

from pkg.version import __version__

import httpx

from pkg.auth import AuthManager, load_auth_config
from pkg.dojo import write_export as write_defectdojo
from pkg.guardrails import GuardedClient
from pkg.integrations import TrackerError, load_integrations, process_tickets
from pkg.observability import github_summary, log_event, metrics_text, write_metrics
from pkg.parser import load_inventory
from pkg.reporter import notify, write_junit, write_sarif
from pkg.rules import load_rules, run_rules
from pkg.results import (apply_baseline, baseline_document, build_document,
                         diff_documents, gate_exit, load_document, write_document)
from pkg.suppressions import apply_suppressions, load_suppressions
from pkg.traffic import (drift_report, import_har, import_mitm, import_postman,
                         load_spec_inventory, load_traffic_inventory,
                         merge_traffic_inventory, write_import)


def positive_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise argparse.ArgumentTypeError("must be finite and positive")
    return result


def positive_int(value: str) -> int:
    result = int(value)
    if result <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return result


def header(value: str) -> tuple[str, str]:
    name, separator, text = value.partition(":")
    name = name.strip()
    text = text.strip()
    if not separator or not name or any(char in text for char in "\r\n"):
        raise argparse.ArgumentTypeError("use NAME:VALUE without newlines")
    return name, text


def mutation(value: str) -> tuple[str, str]:
    method, separator, path = value.partition(":")
    method = method.upper()
    if not separator or method not in {"POST", "PUT", "PATCH", "DELETE", "TRACE"} or not path.startswith("/"):
        raise argparse.ArgumentTypeError("use METHOD:/exact/url-encoded/path")
    if any(char in path for char in "?#\\\r\n") or path.startswith("//"):
        raise argparse.ArgumentTypeError("allowlist entries must be exact paths without query/fragment")
    return method, path


def arguments(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="LedgerProbe spec-driven security automation")
    parser.add_argument("--version", action="version", version="LedgerProbe " + __version__)
    parser.add_argument("--spec", required=True, help="OpenAPI/Swagger or Postman 2.1 file/URL")
    parser.add_argument("--rules", nargs="+", required=True, help="YAML policy files")
    parser.add_argument("--base-url", help="explicitly override every spec server with this target")
    parser.add_argument("--inputs", type=Path, help="JSON file containing contexts and variables")
    parser.add_argument("--auth", type=Path,
                        help="strict ledgerprobe-auth.yaml with pluggable identity providers")
    parser.add_argument("--strict-auth", action="store_true",
                        help="reject legacy static contexts in inputs.json")
    parser.add_argument("--sarif", type=Path, default=Path("results.sarif"))
    parser.add_argument("--junit", type=Path, help="optional JUnit XML output")
    parser.add_argument("--json", type=Path, help="optional versioned JSON results output (required output path for --format defectdojo)")
    parser.add_argument("--format", choices=("results", "defectdojo"), default="results",
                        help="JSON output format; reports remain SARIF/JUnit")
    parser.add_argument("--suppressions", type=Path, help="suppression YAML (default: .ledgerprobe-suppressions.yaml when present)")
    parser.add_argument("--fail-on-stale", action="store_true",
                        help="return exit 1 when a suppression fingerprint was not produced")
    parser.add_argument("--max-suppression-days", type=positive_int, default=180)
    parser.add_argument("--baseline", type=Path, help="previous versioned results JSON for CI gating")
    parser.add_argument("--fail-on", choices=("new", "any", "none"), default="any",
                        help="finding failure policy, optionally relative to --baseline")
    parser.add_argument("--webhooks", type=Path, help="JSON array of webhook configurations (may contain secrets)")
    parser.add_argument("--integrations", type=Path,
                        help="strict tracker/Slack integrations YAML")
    parser.add_argument("--tickets", choices=("dry-run", "plan", "apply", "off"), default="dry-run",
                        help="tracker lifecycle mode; apply is required for network calls")
    parser.add_argument("--fail-on-tracker-error", action="store_true",
                        help="return exit 3 when tracker or Slack delivery fails")
    parser.add_argument("--max-rps", type=positive_float, default=10.0)
    parser.add_argument("--concurrency", type=positive_int, default=4)
    parser.add_argument("--timeout", type=positive_float, default=15.0)
    parser.add_argument("--read-only", action="store_true", help="block all methods except GET/HEAD/OPTIONS")
    parser.add_argument("--allow-mutations", action="store_true",
                        help="allow rules that declare mutating: true (requires a non-read-only scan)")
    parser.add_argument("--allow-host", action="append", default=[], metavar="HOST",
                        help="additional target host permitted for mutating rules; repeatable")
    parser.add_argument("--fail-on-inconclusive", action="store_true",
                        help="return exit 1 when executed checks are inconclusive")
    parser.add_argument("--spec-check", choices=("strict", "warn"), default="strict",
                        help="strict skips endpoints absent from the spec; warn executes them and reports spec_drift")
    parser.add_argument("--inventory", type=Path,
                        help="traffic inventory JSON from `ledgerprobe import`; merges routes only with --spec-check warn")
    parser.add_argument("--accept-generated", action="store_true",
                        help="explicitly accept generated rules carrying review_required: true")
    parser.add_argument("--allow-mutation", action="append", type=mutation, default=[], metavar="METHOD:/path")
    parser.add_argument("--log-format", choices=("text", "json"), default="text")
    parser.add_argument("--metrics-file", type=Path,
                        help="write Prometheus textfile-collector metrics")
    parser.add_argument("--run-id", help="stable scan identifier (default: random)")
    parser.add_argument("--kill-file", type=Path,
                        help="stop gracefully when this file exists")
    parser.add_argument("--environment", choices=("lab", "staging", "production"), default="lab")
    parser.add_argument("--allow-production-read-only", action="store_true",
                        help="explicitly permit a read-only production scan")
    parser.add_argument("--extra-header", action="append", default=[], type=header,
                        metavar="NAME:VALUE", help="non-secret SOC header; repeatable")
    return parser.parse_args(argv)


def read_inputs(path: Path | None) -> dict:
    if path is None:
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) - {"contexts", "variables"}:
        raise ValueError("inputs must contain only contexts and variables")
    if any(not isinstance(value, dict) for value in data.values()):
        raise ValueError("contexts and variables must be objects")
    return data


def target_url(value: str) -> str:
    url = urlsplit(value)
    if (url.scheme not in {"http", "https"} or not url.hostname or url.username is not None
            or url.password is not None or url.query or url.fragment
            or any(char in value for char in "\\\r\n")):
        raise ValueError("target must be an HTTP(S) URL without credentials, query or fragment; use --base-url")
    # Force validation of malformed ports before any scan requests.
    url.port
    return value.rstrip("/")


async def execute(args: argparse.Namespace) -> int:
    started = time.monotonic()
    json_logs = getattr(args, "log_format", "text") == "json"
    # JSON mode reserves stdout for one event object per line.
    _text_print = builtins.print
    print = (lambda *values, **kwargs: None) if json_logs else _text_print
    run_id = getattr(args, "run_id", None) or secrets.token_hex(12)
    if not isinstance(run_id, str) or not run_id or len(run_id) > 160 or any(
            char in run_id for char in "\r\n"):
        raise ValueError("run_id must be a nonempty single-line value")
    environment = getattr(args, "environment", "lab")
    if environment == "production" and args.read_only and not getattr(
            args, "allow_production_read_only", False):
        raise ValueError("production_read_only_requires_allow")
    rules = load_rules(args.rules, accept_generated=args.accept_generated)
    if not rules:
        raise ValueError("at least one rule is required")
    inputs = read_inputs(args.inputs)
    auth_config = load_auth_config(args.auth) if args.auth else None
    if auth_config is not None:
        for name, identity in auth_config["identities"].items():
            if identity["environment"] != environment:
                print(f"[ERROR] environment_mismatch: identity {name} is {identity['environment']}, run is {environment}", file=sys.stderr)
                return 2
    if inputs.get("contexts") and auth_config is not None:
        raise ValueError("use --auth or legacy inputs.json contexts, not both")
    if inputs.get("contexts") and auth_config is None:
        if args.strict_auth:
            raise ValueError("legacy_static_credentials: migrate inputs.json contexts to --auth")
        print("[!] legacy_static_credentials: inputs.json static contexts are deprecated",
              file=sys.stderr)
    webhooks = []
    if args.webhooks:
        webhooks = json.loads(args.webhooks.read_text(encoding="utf-8"))
        if not isinstance(webhooks, list):
            raise ValueError("webhooks must be a JSON array")
        # Validate before touching the target, even when there will be no findings.
        await notify([], webhooks, None)
    default_headers = {"User-Agent": f"LedgerProbe/{__version__}",
                       "X-LedgerProbe-Run": run_id}
    if auth_config:
        default_headers.update(auth_config.get("extra_headers", {}))
    default_headers.update(dict(getattr(args, "extra_header", []) or []))
    async with GuardedClient(max_rps=args.max_rps, concurrency=args.concurrency,
                             read_only=args.read_only, allow_mutations=args.allow_mutation,
                             timeout=args.timeout, default_headers=default_headers,
                             kill_file=args.kill_file) as client:
        inventory = await load_inventory(args.spec, client)
        inventory["base_url"] = target_url(args.base_url or inventory["base_url"])
        if args.base_url:
            # An explicit CLI override authorizes one target for the whole scan.
            for endpoint in inventory["endpoints"]:
                endpoint.pop("base_url", None)
        drift = None
        if args.inventory:
            traffic = load_traffic_inventory(args.inventory)
            drift = drift_report(inventory, traffic)
            if args.spec_check == "warn":
                merge_traffic_inventory(inventory, traffic)
        print(f"[*] {len(inventory['endpoints'])} endpoints; {len(inventory['graph'])} dependency candidates")
        auth_manager = None
        contexts = inputs.get("contexts", {})
        variables = inputs.get("variables", {})
        if auth_config is not None:
            auth_manager = AuthManager(auth_config, variables, inventory["base_url"], client,
                                       allowed_hosts=args.allow_host)
        try:
            if auth_manager is not None:
                await auth_manager.setup()
                contexts = await auth_manager.initialize()
                variables = auth_manager.variables
            results = await run_rules(
                inventory, rules, client, contexts=contexts, variables=variables,
                spec_check=args.spec_check, allow_mutations=args.allow_mutations,
                allowed_hosts=args.allow_host, read_only=args.read_only,
                accept_generated=args.accept_generated, auth_manager=auth_manager,
                environment=environment,
            )
        finally:
            if auth_manager is not None:
                await auth_manager.teardown()
    warnings = []
    suppression_stats = None
    suppressions_path = args.suppressions
    if suppressions_path is None and Path(".ledgerprobe-suppressions.yaml").exists():
        suppressions_path = Path(".ledgerprobe-suppressions.yaml")
    if suppressions_path is not None:
        entries = load_suppressions(suppressions_path, max_days=args.max_suppression_days)
        results, suppression_stats, suppression_warnings = apply_suppressions(results, entries)
        warnings.extend(suppression_warnings)
    baseline_stats = None
    if args.baseline:
        results, baseline_stats = apply_baseline(results, baseline_document(args.baseline))
    source_uri = None
    if urlsplit(args.spec).scheme not in {"http", "https"}:
        try:
            source_uri = quote(Path(args.spec).resolve().relative_to(Path(__file__).parent).as_posix(), safe="/")
        except ValueError:
            pass  # External specs have endpoint-only SARIF locations.
    report_results = results
    if baseline_stats is not None:
        report_results = [result for result in results
                          if result.get("baseline_status") in {"new", "unchanged"}]
    write_sarif(report_results, args.sarif, source_uri=source_uri, warnings=warnings)
    if args.junit:
        write_junit(report_results, args.junit, warnings=warnings)
    if args.format == "defectdojo" and args.json is None:
        raise ValueError("--format defectdojo requires --json OUTPUT")
    if args.json and args.format == "defectdojo":
        write_defectdojo(results, args.json, target=inventory["base_url"])
    elif args.json:
        document = build_document(results, target=inventory["base_url"],
                                  modes={"read_only": args.read_only,
                                         "allow_mutations": args.allow_mutations,
                                         "spec_check": args.spec_check},
                                  warnings=warnings, baseline=baseline_stats,
                                  suppressions=suppression_stats, drift=drift)
        write_document(document, args.json)
    counts = Counter(result["status"] for result in results)
    target_label = urlsplit(inventory["base_url"]).netloc
    if json_logs:
        duration = time.monotonic() - started
        for result in results:
            log_event(run_id, "check", target=target_label, tool_version=__version__,
                      result=result, duration_ms=duration * 1000)
        verdicts = Counter(result.get("verdict", "UNKNOWN") for result in results)
        inconclusive = counts.get("inconclusive", 0) / max(1, len(results))
        log_event(run_id, "run_summary", target=target_label, tool_version=__version__,
                  duration_ms=duration * 1000,
                  extra={"status_counts": dict(counts),
                         "verdict_counts": dict(verdicts),
                         "inconclusive_rate": inconclusive})
    for result in results:
        if result.get("spec_drift"):
            if str(result["spec_drift"]).startswith("traffic inventory:"):
                print(f"[!] spec_drift: route came from traffic inventory ({result['spec_drift']}); executed because --spec-check warn")
            else:
                print(f"[!] spec_drift: {result['spec_drift']} is absent from the spec; executed because --spec-check warn")
        print(f"[{result['status']}] {result['rule_id']} {result['method']} {result['path']}: {result['message']}")
    if baseline_stats is not None:
        print(f"[+] baseline: new={baseline_stats['new']} unchanged={baseline_stats['unchanged']} "
              f"resolved={baseline_stats['resolved']}")
    for warning in warnings:
        if warning.get("code") == "suppression_expired":
            print(f"[!] suppression_expired: owner={warning.get('owner')} expires={warning.get('expires')}")
        elif warning.get("code") == "stale_suppression":
            print(f"[!] stale_suppression: {warning.get('fingerprint')}")
    print(f"[+] SARIF: {args.sarif}; {dict(counts)}")
    if webhooks:
        # Outbound notifications are explicitly opted-in writes, not target mutations.
        async with GuardedClient(max_rps=args.max_rps, concurrency=1, timeout=args.timeout) as client:
            await notify(results, webhooks, client)
    tracker_failed = False
    if args.tickets != "off":
        integrations_path = args.integrations or Path("ledgerprobe-integrations.yaml")
        if integrations_path.exists():
            config = load_integrations(integrations_path)
            try:
                ticket_run = await process_tickets(
                    results, config=config, target=inventory["base_url"], mode=args.tickets,
                    ci_url=os.environ.get("CI_RUN_URL"),
                )
            except TrackerError as exc:
                ticket_run = None
                tracker_failed = True
                print(f"[!] tracker_error: {exc}", file=sys.stderr)
            if ticket_run is None:
                pass
            else:
                tracker_failed = bool(ticket_run.errors)
                for warning in ticket_run.warnings:
                    print(f"[!] tickets: {warning}")
                for error in ticket_run.errors:
                    print(f"[!] tracker_error: {error}", file=sys.stderr)
        elif args.integrations:
            raise ValueError("integrations configuration does not exist")
    # Errors mean the scan could not be trusted. Inconclusive checks completed
    # safely but do not establish an authorization verdict unless opted into CI failure.
    exit_code = gate_exit(results, fail_on=args.fail_on,
                          fail_on_inconclusive=args.fail_on_inconclusive,
                          fail_on_stale=args.fail_on_stale,
                          stale=(suppression_stats or {}).get("stale", 0))
    if args.metrics_file:
        write_metrics(args.metrics_file, metrics_text(
            results, duration_seconds=time.monotonic() - started,
            tracker_errors=int(tracker_failed)))
    if any(result.get("reason") == "kill_switch" for result in results):
        return 4
    if tracker_failed and args.fail_on_tracker_error and exit_code != 2:
        return 3
    return exit_code


def main(argv=None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if values[:1] == ["import"]:
        return _import_main(values[1:])
    if values[:1] == ["drift"]:
        return _drift_main(values[1:])
    if values[:1] == ["diff"]:
        parser = argparse.ArgumentParser(description="Compare two LedgerProbe results JSON files")
        parser.add_argument("old")
        parser.add_argument("new")
        try:
            parsed = parser.parse_args(values[1:])
            print(json.dumps(diff_documents(load_document(parsed.old), load_document(parsed.new)),
                             indent=2, sort_keys=True))
            return 0
        except (ValueError, OSError):
            print("error: results diff failed (schema mismatch or unreadable input)", file=sys.stderr)
            return 2
    args = arguments(values)
    try:
        return asyncio.run(execute(args))
    except (ValueError, OSError, ImportError, httpx.HTTPError) as exc:
        # Exception text from HTTP clients/JSON parsers can include credentials.
        print(f"error: scan/configuration failure ({type(exc).__name__}); verify spec, inputs, target and webhook configuration", file=sys.stderr)
        return 2


def _roles(values: list[str]) -> dict[str, Path]:
    roles = {}
    for value in values:
        name, separator, path = value.partition("=")
        if not separator or not name.strip() or not path.strip() or name in roles:
            raise ValueError("--role entries must be unique name=file pairs")
        roles[name] = Path(path)
    return roles


def _import_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ledgerprobe import",
                                     description="Offline traffic import and generated rule scaffolding")
    formats = parser.add_subparsers(dest="format", required=True)
    for name in ("har", "postman", "mitm"):
        command = formats.add_parser(name)
        command.add_argument("--role", action="append", required=True, metavar="NAME=FILE",
                             help="label a capture with a role; repeat for owner/other")
        command.add_argument("--include-host", action="append", required=True, metavar="HOST",
                             help="keep only this host; repeatable")
        command.add_argument("--spec", type=Path, help="optional OpenAPI document for drift")
        command.add_argument("--out", type=Path, required=True, help="artifact directory")
        command.add_argument("--allow-tracked-output", action="store_true",
                             help="explicitly allow inputs.generated.json outside .gitignore")
    return parser


def _import_main(argv: list[str]) -> int:
    try:
        parsed = _import_parser().parse_args(argv)
        roles = _roles(parsed.role)
        importer = {"har": import_har, "postman": import_postman, "mitm": import_mitm}[parsed.format]
        result = importer(roles, parsed.include_host, spec=parsed.spec)
        if result.drift is None:
            result.drift = {"counts": {"undocumented": 0, "unobserved": 0,
                                        "parameter_mismatches": 0, "method_mismatches": 0},
                            "undocumented": [], "unobserved": [],
                            "parameter_mismatches": [], "method_mismatches": []}
        paths = write_import(result, parsed.out, allow_tracked_output=parsed.allow_tracked_output)
    except (ValueError, OSError, ImportError) as exc:
        print(f"error: import failed ({type(exc).__name__}); verify capture paths, host filters and output location",
              file=sys.stderr)
        return 2
    print(f"[*] wrote {len(result.inventory['endpoints'])} traffic endpoints and {len(result.rules)} generated rules")
    for path in paths:
        print(f"[*] {path}")
    if result.inventory.get("graphql_operations"):
        print("[!] GraphQL operations require manual rules:")
        for operation in result.inventory["graphql_operations"]:
            print(f"    {operation['type']} {operation['name']}")
    if any(rule.get("disabled") for rule in result.rules):
        print("[!] mutation rules were emitted disabled; add restore/verify before enabling")
    print("[!] inputs.generated.json contains local object IDs/canaries; review it before filling token placeholders")
    return 0


def _drift_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="ledgerprobe drift",
                                     description="Compare OpenAPI routes with traffic inventory")
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--fail-on-drift", action="store_true",
                        help="exit 1 when traffic contains undocumented endpoints")
    try:
        parsed = parser.parse_args(argv)
        report = drift_report(load_spec_inventory(parsed.spec), load_traffic_inventory(parsed.inventory))
    except (ValueError, OSError, ImportError) as exc:
        print(f"error: drift failed ({type(exc).__name__}); verify OpenAPI and inventory paths", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if parsed.fail_on_drift and report["undocumented"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
