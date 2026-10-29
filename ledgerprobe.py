"""Spec-driven security checks, independent of the bundled banking lab."""
from __future__ import annotations

import argparse
import asyncio
import json
import math
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx

from pkg.guardrails import GuardedClient
from pkg.parser import load_inventory
from pkg.reporter import notify, write_junit, write_sarif
from pkg.rules import load_rules, run_rules


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
    parser.add_argument("--spec", required=True, help="OpenAPI/Swagger or Postman 2.1 file/URL")
    parser.add_argument("--rules", nargs="+", required=True, help="YAML policy files")
    parser.add_argument("--base-url", help="explicitly override every spec server with this target")
    parser.add_argument("--inputs", type=Path, help="JSON file containing contexts and variables")
    parser.add_argument("--sarif", type=Path, default=Path("results.sarif"))
    parser.add_argument("--junit", type=Path, help="optional JUnit XML output")
    parser.add_argument("--webhooks", type=Path, help="JSON array of webhook configurations (may contain secrets)")
    parser.add_argument("--max-rps", type=positive_float, default=10.0)
    parser.add_argument("--concurrency", type=positive_int, default=4)
    parser.add_argument("--timeout", type=positive_float, default=15.0)
    parser.add_argument("--read-only", action="store_true", help="block all methods except GET/HEAD/OPTIONS")
    parser.add_argument("--fail-on-inconclusive", action="store_true",
                        help="return exit 1 when executed checks are inconclusive")
    parser.add_argument("--allow-mutation", action="append", type=mutation, default=[], metavar="METHOD:/path")
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
    rules = load_rules(args.rules)
    if not rules:
        raise ValueError("at least one rule is required")
    inputs = read_inputs(args.inputs)
    webhooks = []
    if args.webhooks:
        webhooks = json.loads(args.webhooks.read_text(encoding="utf-8"))
        if not isinstance(webhooks, list):
            raise ValueError("webhooks must be a JSON array")
        # Validate before touching the target, even when there will be no findings.
        await notify([], webhooks, None)
    async with GuardedClient(max_rps=args.max_rps, concurrency=args.concurrency,
                             read_only=args.read_only, allow_mutations=args.allow_mutation,
                             timeout=args.timeout) as client:
        inventory = await load_inventory(args.spec, client)
        inventory["base_url"] = target_url(args.base_url or inventory["base_url"])
        if args.base_url:
            # An explicit CLI override authorizes one target for the whole scan.
            for endpoint in inventory["endpoints"]:
                endpoint.pop("base_url", None)
        print(f"[*] {len(inventory['endpoints'])} endpoints; {len(inventory['graph'])} dependency candidates")
        results = await run_rules(inventory, rules, client, **inputs)
    source_uri = None
    if urlsplit(args.spec).scheme not in {"http", "https"}:
        try:
            source_uri = quote(Path(args.spec).resolve().relative_to(Path(__file__).parent).as_posix(), safe="/")
        except ValueError:
            pass  # External specs have endpoint-only SARIF locations.
    write_sarif(results, args.sarif, source_uri=source_uri)
    if args.junit:
        write_junit(results, args.junit)
    counts = Counter(result["status"] for result in results)
    for result in results:
        print(f"[{result['status']}] {result['rule_id']} {result['method']} {result['path']}: {result['message']}")
    print(f"[+] SARIF: {args.sarif}; {dict(counts)}")
    if webhooks:
        # Outbound notifications are explicitly opted-in writes, not target mutations.
        async with GuardedClient(max_rps=args.max_rps, concurrency=1, timeout=args.timeout) as client:
            await notify(results, webhooks, client)
    # Errors mean the scan could not be trusted. Inconclusive checks completed
    # safely but do not establish an authorization verdict unless opted into CI failure.
    if counts["error"] or not counts["passed"] + counts["failed"] + counts["inconclusive"]:
        return 2
    if counts["failed"] or (args.fail_on_inconclusive and counts["inconclusive"]):
        return 1
    return 0


def main(argv=None) -> int:
    args = arguments(argv)
    try:
        return asyncio.run(execute(args))
    except (ValueError, OSError, ImportError, httpx.HTTPError) as exc:
        # Exception text from HTTP clients/JSON parsers can include credentials.
        print(f"error: scan/configuration failure ({type(exc).__name__}); verify spec, inputs, target and webhook configuration", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
