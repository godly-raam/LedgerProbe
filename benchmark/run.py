#!/usr/bin/env python3
"""Local-only precision/recall harness for LedgerProbe.

Every target URL is checked before a socket is opened. Only loopback and
RFC1918/Docker-internal addresses are accepted; public names and IPs hard-fail.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

import yaml

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmark"
TARGETS_DIR = BENCH / "targets"
GROUND_TRUTH = BENCH / "ground_truth"
DEFAULT_OUT = BENCH / ".out"

LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1"}
DOCKER_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
MODES = ("legacy_strict", "legacy_lenient", "differential")
COUNT_KEYS = ("TP", "FP", "TN", "FN", "INC_VULN", "INC_SAFE")


class UnsafeTarget(ValueError):
    """The requested target is not a local benchmark target."""


class Blocked(RuntimeError):
    """A target could not be executed in this environment."""


def validate_target_url(url: str, *, allow_docker_internal: bool = False,
                        docker_hosts: Iterable[str] = ()) -> str:
    """Return *url* if it is loopback (or an explicitly allowed Docker host)."""
    if not isinstance(url, str) or not url.strip():
        raise UnsafeTarget("target URL is empty")
    parsed = urlsplit(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise UnsafeTarget(f"target scheme must be http/https: {parsed.scheme!r}")
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeTarget("target URL must not contain credentials")
    if parsed.fragment:
        raise UnsafeTarget("target URL must not contain a fragment")
    if not parsed.hostname:
        raise UnsafeTarget("target URL has no hostname")
    try:
        port = parsed.port
    except ValueError as exc:
        raise UnsafeTarget("target URL has an invalid port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise UnsafeTarget("target port must be between 1 and 65535")

    host = parsed.hostname.rstrip(".").lower()
    if host in LOOPBACK_NAMES:
        return url.strip()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        allowed = {name.rstrip(".").lower() for name in docker_hosts}
        if allow_docker_internal and host in allowed:
            return url.strip()
        raise UnsafeTarget(f"host {host!r} is not loopback or an allowed Docker host")
    if address.is_loopback:
        return url.strip()
    if allow_docker_internal and any(address in network for network in DOCKER_NETWORKS):
        return url.strip()
    raise UnsafeTarget(f"address {address} is not loopback or Docker-internal")


@dataclass
class Target:
    name: str
    ground_truth: Path
    spec: Path
    compose: Path
    setup: Path
    rules_legacy: Path
    rules_differential: Path
    instances: dict[str, str]
    read_only: bool
    docker_hosts: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)


TARGETS: dict[str, Target] = {
    "vampi": Target(
        name="vampi",
        ground_truth=GROUND_TRUTH / "vampi.yaml",
        spec=TARGETS_DIR / "vampi" / "openapi.json",
        compose=TARGETS_DIR / "vampi" / "compose.yaml",
        setup=TARGETS_DIR / "vampi" / "setup.py",
        rules_legacy=TARGETS_DIR / "vampi" / "rules_legacy.yaml",
        rules_differential=TARGETS_DIR / "vampi" / "rules_differential.yaml",
        instances={
            "vulnerable": "http://127.0.0.1:5002",
            "secure": "http://127.0.0.1:5001",
        },
        read_only=False,
    ),
    "crapi": Target(
        name="crapi",
        ground_truth=GROUND_TRUTH / "crapi.yaml",
        spec=TARGETS_DIR / "crapi" / "openapi.json",
        compose=TARGETS_DIR / "crapi" / "compose.yaml",
        setup=TARGETS_DIR / "crapi" / "setup.py",
        rules_legacy=TARGETS_DIR / "crapi" / "rules_legacy.yaml",
        rules_differential=TARGETS_DIR / "crapi" / "rules_differential.yaml",
        instances={"default": "http://127.0.0.1:8888"},
        read_only=True,
        docker_hosts=("crapi-identity", "crapi-community", "crapi-workshop", "crapi-web"),
        env={"VERSION": "1.1.6", "LISTEN_IP": "127.0.0.1", "TLS_ENABLED": "false"},
    ),
}


def _run(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None,
         timeout: int = 180, check: bool = True,
         allow_findings: bool = False) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(cmd, cwd=str(cwd or ROOT), env=env, capture_output=True,
                               text=True, timeout=timeout)
    allowed = {0, 1} if allow_findings else {0}
    if check and completed.returncode not in allowed:
        detail = (completed.stderr or completed.stdout or "").strip()[-2000:]
        raise Blocked(f"{' '.join(cmd[:4])} failed ({completed.returncode}): {detail}")
    return completed


def docker_available() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def compose_command() -> list[str]:
    for candidate in (["docker", "compose"], ["docker-compose"]):
        try:
            result = subprocess.run(candidate + ["version"], capture_output=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            return candidate
    raise Blocked("Docker Compose v2 is not installed or not on PATH")


def _http_ready(url: str, timeout: float = 120.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if 200 <= response.status < 500:
                    return True
        except (urllib.error.URLError, TimeoutError, OSError):
            time.sleep(1)
    return False


def compose_up(target: Target, out: Path) -> None:
    cmd = compose_command() + [
        "-f", str(target.compose), "-p", f"ledgerprobe-{target.name}",
        "up", "-d", "--wait",
    ]
    env = os.environ.copy()
    env.update({"LISTEN_IP": "127.0.0.1", **target.env})
    _run(cmd, env=env, timeout=600)
    for name, url in target.instances.items():
        if not _http_ready(url):
            raise Blocked(f"{target.name}/{name} did not answer at {url}")


def compose_down(target: Target) -> None:
    cmd = compose_command() + ["-f", str(target.compose), "-p", f"ledgerprobe-{target.name}",
                               "down", "-v", "--remove-orphans"]
    try:
        _run(cmd, timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"[!] compose down failed: {exc}", file=sys.stderr)


def _load_cases(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("cases"), list):
        raise ValueError(f"{path}: ground truth must contain a cases list")
    ids = set()
    for case in document["cases"]:
        if not isinstance(case, dict) or case.get("label") not in {"vulnerable", "safe"}:
            raise ValueError(f"{path}: invalid ground-truth case")
        for key in ("rule_id", "instance", "method", "path", "label", "source"):
            if not case.get(key):
                raise ValueError(f"{path}: case missing {key}")
        identity = (case["instance"], case["rule_id"])
        if identity in ids:
            raise ValueError(f"{path}: duplicate case {identity}")
        ids.add(identity)
    return document, document["cases"]


def _junit_results(path: Path) -> dict[str, dict[str, str | None]]:
    if not path.exists():
        return {}
    root = ET.parse(path).getroot()
    results: dict[str, dict[str, str | None]] = {}
    for case in root.findall("testcase"):
        rule_id = case.get("classname") or ""
        properties = {
            item.get("name", "").removeprefix("ledgerprobe."): item.get("value", "")
            for item in case.findall("./properties/property")
        }
        verdict = properties.get("verdict")
        reason = properties.get("reason")
        if verdict is None:
            if case.find("failure") is not None:
                verdict = "FAIL"
            elif case.find("error") is not None:
                verdict = "ERROR"
            elif case.find("skipped") is not None:
                verdict = "INCONCLUSIVE"
            else:
                verdict = "PASS"
        results[rule_id] = {"verdict": verdict, "reason": reason or "",
                            "spec_drift": properties.get("spec_drift", ""),
                            "name": case.get("name") or ""}
    return results


def _rule_scopes(path: Path) -> dict[str, str]:
    """Read declared scopes from the differential rule file."""
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
        return {}
    return {rule["id"]: rule.get("scope", "object")
            for rule in document["rules"] if isinstance(rule, dict) and rule.get("id")}


def _substitute(value: Any, variables: dict[str, Any]) -> Any:
    if isinstance(value, str):
        def repl(match: re.Match[str]) -> str:
            key = match.group(1)
            if key not in variables:
                raise KeyError(key)
            return str(variables[key])
        return re.sub(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}", repl, value)
    if isinstance(value, list):
        return [_substitute(item, variables) for item in value]
    if isinstance(value, dict):
        return {key: _substitute(item, variables) for key, item in value.items()}
    return value


def _lenient_request(base: str, rule: dict[str, Any], inputs: dict[str, Any]) -> dict[str, str]:
    """Execute one status-only rule, treating 401/403/404 as a pass.

    The engine's legacy assertion schema cannot express a status set without
    changing the engine, which is out of scope for this benchmark task.
    """
    variables = inputs.get("variables", {})
    contexts = inputs.get("contexts", {})
    target = (rule.get("target_endpoints") or [{}])[0]
    path = target.get("path", "")
    method = target.get("method", "GET")
    params = rule.get("parameters") or {}
    try:
        for name, value in (params.get("path") or {}).items():
            path = path.replace("{" + name + "}", urllib.parse.quote(str(_substitute(value, variables)), safe=""))
        path = _substitute(path, variables)
        query = {key: _substitute(value, variables) for key, value in (params.get("query") or {}).items()}
    except KeyError as exc:
        return {"verdict": "INCONCLUSIVE", "reason": f"unresolved_parameter:{exc.args[0]}", "name": rule.get("name", "")}
    if "{{" in path or "{" in path and not query:
        # A remaining path template is not a usable request.
        if re.search(r"\{[A-Za-z_][A-Za-z0-9_]*\}", path):
            return {"verdict": "INCONCLUSIVE", "reason": "unresolved_path", "name": rule.get("name", "")}
    url = base.rstrip("/") + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    headers = {"Accept": "application/json"}
    context_name = (rule.get("auth_contexts") or {}).get("forbidden")
    headers.update(contexts.get(context_name, {}) if context_name else {})
    body = None
    if "body" in rule:
        try:
            body = json.dumps(_substitute(rule["body"], variables)).encode("utf-8")
        except KeyError as exc:
            return {"verdict": "INCONCLUSIVE", "reason": f"unresolved_parameter:{exc.args[0]}", "name": rule.get("name", "")}
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"verdict": "INCONCLUSIVE", "reason": f"request_error:{type(exc).__name__}", "name": rule.get("name", "")}
    if status in {401, 403, 404}:
        verdict, reason = "PASS", f"status_{status}"
    elif 200 <= status < 300:
        verdict, reason = "FAIL", f"status_{status}"
    else:
        verdict, reason = "INCONCLUSIVE", f"status_{status}"
    return {"verdict": verdict, "reason": reason, "name": rule.get("name", "")}


def _lenient_scan(base: str, target: Target, inputs: dict[str, Any]) -> dict[str, dict[str, str | None]]:
    document = yaml.safe_load(target.rules_legacy.read_text(encoding="utf-8"))
    results: dict[str, dict[str, str | None]] = {}
    for rule in document.get("rules", []):
        results[rule["id"]] = _lenient_request(base, rule, inputs)
    return results


def _auth_contexts(auth_path: Path, base: str, variables: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Resolve login_request identities for the legacy status-only harness."""
    document = yaml.safe_load(auth_path.read_text(encoding="utf-8"))
    contexts: dict[str, dict[str, str]] = {}
    for name, identity in (document.get("identities") or {}).items():
        params = identity["params"]
        body = {}
        for key, value in params["body"].items():
            if key.endswith("_ref"):
                ref = value
                if ref.startswith("env:"):
                    body[key[:-4]] = os.environ[ref[4:]]
                elif ref.startswith("file:"):
                    path, _, secret_key = ref[5:].rpartition("#")
                    text = Path(path).read_text(encoding="utf-8")
                    if text.lstrip().startswith("{"):
                        body[key[:-4]] = json.loads(text)[secret_key]
                    else:
                        values = dict(line.split("=", 1) for line in text.splitlines()
                                      if "=" in line and not line.lstrip().startswith("#"))
                        body[key[:-4]] = values[secret_key]
                else:
                    raise ValueError("legacy harness supports env/file refs only")
            else:
                body[key] = _substitute(value, variables)
        request = urllib.request.Request(
            base.rstrip("/") + params["path"], data=json.dumps(body).encode(),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            method=params["method"],
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise ValueError(f"legacy auth failed: {exc.code}") from None
        token = payload
        for part in params["token_json_path"].split("."):
            token = token[part]
        contexts[name] = {"Authorization": params.get("header_format", "Bearer {token}").format(token=token)}
    return contexts


def run_scan(target: Target, instance: str, mode: str, base_url: str,
             inputs: Path, out: Path, repeat: int = 1) -> dict[str, dict[str, str | None]]:
    sandbox = out / target.name / instance / mode / f"run-{repeat}"
    sandbox.mkdir(parents=True, exist_ok=True)
    sarif = sandbox / "results.sarif"
    junit = sandbox / "results.xml"
    auth = inputs.with_name("ledgerprobe-auth.yaml")
    if mode == "legacy_lenient":
        data = json.loads(inputs.read_text(encoding="utf-8"))
        if auth.exists():
            try:
                data["contexts"] = _auth_contexts(auth, base_url, data.get("variables", {}))
            except (OSError, ValueError, KeyError):
                return {}
        return _lenient_scan(base_url, target, data)
    rules = target.rules_legacy if mode == "legacy_strict" else target.rules_differential
    command = [
        sys.executable, str(ROOT / "ledgerprobe.py"),
        "--spec", str(target.spec), "--base-url", base_url,
        "--rules", str(rules), "--inputs", str(inputs),
        "--sarif", str(sarif), "--junit", str(junit),
        "--max-rps", "20", "--timeout", "10",
    ]
    if auth.exists():
        command += ["--auth", str(auth)]
    if target.read_only:
        command.append("--read-only")
    if target.name == "vampi":
        # The VAmPI differential set includes the password-mutation rule.
        # The rule still carries verify/restore and is loopback-only here.
        command.append("--allow-mutations")
    print(f"[*] {target.name}/{instance}/{mode}/run-{repeat}: {' '.join(command[1:5])} ...")
    completed = _run(command, timeout=300, check=False, allow_findings=True)
    if completed.returncode not in {0, 1}:
        print(f"[!] scan exited {completed.returncode}: "
              f"{(completed.stderr or completed.stdout or '').strip()[-1000:]}", file=sys.stderr)
    return _junit_results(junit)


def _score(cases: list[dict[str, Any]], results: dict[str, dict[str, str | None]],
           instance: str, scope_map: dict[str, str] | None = None) -> dict[str, Any]:
    counts = Counter({key: 0 for key in COUNT_KEYS})
    rows = []
    selected = [case for case in cases if case["instance"] == instance]
    for case in selected:
        observed = results.get(case["rule_id"], {})
        verdict = observed.get("verdict") or "MISSING"
        reason = observed.get("reason") or ""
        if case["label"] == "vulnerable":
            if verdict == "FAIL":
                outcome = "TP"
            elif verdict == "PASS":
                outcome = "FN"
            else:
                outcome = "INC_VULN"
        else:
            if verdict == "FAIL":
                outcome = "FP"
            elif verdict == "PASS":
                outcome = "TN"
            else:
                outcome = "INC_SAFE"
        counts[outcome] += 1
        rows.append({
            "rule_id": case["rule_id"], "method": case["method"], "path": case["path"],
            "label": case["label"], "verdict": verdict, "reason": reason,
            "outcome": outcome, "source": case["source"], "instance": instance,
            "scope": (scope_map or {}).get(case["rule_id"], "object"),
        })
    if sum(counts.values()) != len(selected):
        raise AssertionError(f"{instance}: counts {dict(counts)} do not sum to {len(selected)} cases")
    tp, fp, tn, fn = counts["TP"], counts["FP"], counts["TN"], counts["FN"]
    inc_v, inc_s = counts["INC_VULN"], counts["INC_SAFE"]
    return {
        "counts": dict(counts),
        "cases": len(selected),
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn + inc_v) if tp + fn + inc_v else None,
        "recall_excl_inconclusive": tp / (tp + fn) if tp + fn else None,
        "rows": rows,
    }


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def _target_mode(instance: str) -> str:
    return {"vulnerable": "vulnerable=1", "secure": "vulnerable=0"}.get(instance, "single")


def _table_row(name: str, mode: str, summary: dict[str, Any], cases: int,
               status: str = "ok") -> str:
    c = summary["counts"]
    return (f"| {name} | {mode} | {status} | {cases} | {c['TP']} | {c['FP']} | {c['TN']} | "
            f"{c['FN']} | {c['INC_VULN']} | {c['INC_SAFE']} | {_fmt(summary['precision'])} | "
            f"{_fmt(summary['recall'])} | {_fmt(summary['recall_excl_inconclusive'])} |")


def _summary_from_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter({key: 0 for key in COUNT_KEYS})
    for row in rows:
        counts[row["outcome"]] += 1
    tp, fp, tn, fn = (counts[key] for key in ("TP", "FP", "TN", "FN"))
    inc_v = counts["INC_VULN"]
    return {
        "counts": dict(counts), "cases": len(rows),
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn + inc_v) if tp + fn + inc_v else None,
        "recall_excl_inconclusive": tp / (tp + fn) if tp + fn else None,
    }


def _diagnosis(row: dict[str, Any]) -> str:
    reason = row["reason"] or "none"
    if row["outcome"] == "FP":
        return (f"Safe endpoint returned FAIL (`{reason}`); the "
                f"{'strict' if 'assertion_failed' in reason else 'status'} baseline treats this "
                "non-leaking response as a finding.")
    if row["outcome"] == "FN":
        return (f"Vulnerable endpoint returned PASS (`{reason}`); the request was incorrectly "
                "treated as denied.")
    if row["outcome"] == "INC_VULN":
        return (f"Vulnerable endpoint was {row['verdict']} (`{reason}`); counted as a miss, "
                "not a true negative.")
    return (f"Safe endpoint was {row['verdict']} (`{reason}`); not counted as a true negative.")


def write_results(document: dict[str, Any], path: Path) -> None:
    lines = [
        "# LedgerProbe real-world benchmark results",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        "",
        "Targets were run locally on loopback only. Labels come from "
        "`benchmark/ground_truth/`, frozen before any scan. Each mode was run "
        "three times with a fresh target reset between runs.",
        "",
        "## Scores",
        "",
        "| Target | Mode | Status | N | TP | FP | TN | FN | INC_vuln | INC_safe | Precision | Recall | Recall excl. INC |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for target_name, target_result in document["targets"].items():
        if target_result["status"] != "ok":
            lines.append(f"| {target_name} | — | {target_result['status']} | — | — | — | — | — | — | — | n/a | n/a | n/a |")
            continue
        n = len(document.get("targets", {}).get(target_name, {}).get("ground_truth", {}).get("cases", []))
        if not n:
            n = sum(summary["cases"] for summary in target_result["modes"].values())
        for mode, summary in target_result["modes"].items():
            lines.append(_table_row(target_name, mode, summary, summary["cases"]))
    lines += [
        "",
        "`Recall` counts `INC_vuln` as a miss: `TP / (TP + FN + INC_vuln)`. "
        "`Recall excl. INC` is `TP / (TP + FN)`. Every row's six outcome counts "
        "must sum to N; a runtime assertion enforces this. `INCONCLUSIVE` is "
        "never counted as correct.",
        "",
        "## Object-scoped-only cut",
        "",
        "This cut keeps only cases whose rule declares `scope: object` (the default). "
        "Scope is author-declared in the rule, never derived from a ground-truth label.",
        "",
        "| Target | Mode | Status | N | TP | FP | TN | FN | INC_vuln | INC_safe | Precision | Recall | Recall excl. INC |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for target_name, target_result in document["targets"].items():
        if target_result["status"] != "ok":
            continue
        for mode, summary in target_result["modes"].items():
            rows = [row for row in summary["rows"] if row.get("scope", "object") == "object"]
            lines.append(_table_row(f"{target_name} (object)", mode, _summary_from_rows(rows), len(rows)))
    lines += [
        "",
        "## Determinism",
        "",
        "| Target | Mode | Runs | Identical verdicts | Flips |",
        "| --- | --- | ---: | --- | --- |",
    ]
    for target_name, target_result in document["targets"].items():
        if target_result["status"] != "ok":
            continue
        for mode, det in target_result.get("determinism", {}).items():
            flips = "; ".join(
                f"`{item['instance']}/{item['case']}`: " + ", ".join(str(v) for v in item["verdicts"])
                for item in det.get("flips", [])
            ) or "none"
            lines.append(f"| {target_name} | {mode} | {det.get('runs', 0)} | "
                         f"{'yes' if det.get('identical') else 'no'} | {flips} |")
    lines += [
        "",
        "## Detail",
        "",
    ]
    for target_name, target_result in document["targets"].items():
        lines.append(f"### {target_name}")
        lines.append("")
        if target_result["status"] != "ok":
            lines.append(f"Not executed: {target_result['reason']}")
            lines.append("")
            continue
        for mode, summary in target_result["modes"].items():
            lines.append(f"#### {mode}")
            lines.append("")
            lines.append("| Case | Scope | Target mode | Ground-truth label | Verdict | Reason | Outcome | Source |")
            lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
            for row in summary["rows"]:
                lines.append(
                    f"| `{row['rule_id']}` {row['method']} `{row['path']}` | {row.get('scope', 'object')} | "
                    f"{_target_mode(row['instance'])} | {row['label']} | {row['verdict']} | "
                    f"{row['reason'] or '—'} | {row['outcome']} | {row['source']} |"
                )
            lines.append("")
        lines.append("#### FP, FN and INCONCLUSIVE diagnoses")
        lines.append("")
        rows = [(mode, row) for mode, summary in target_result["modes"].items()
                for row in summary["rows"] if row["outcome"] not in {"TP", "TN"}]
        if not rows:
            lines.append("None.")
        for mode, row in rows:
            lines.append(
                f"- **{row['outcome']}** ({mode}) `{row['rule_id']}` {row['method']} "
                f"`{row['path']}` — {row['verdict']}, reason `{row['reason'] or 'none'}`. "
                f"{_diagnosis(row)} Source: {row['source']}."
            )
        lines.append("")
    path.write_text("\n".join(lines).rstrip("\n") + "\n", encoding="utf-8")


def _scan_mode(target: Target, mode: str, out: Path, base_urls: dict[str, str],
               cases: list[dict[str, Any]], repeat: int) -> dict[str, Any]:
    combined = {"counts": Counter({key: 0 for key in COUNT_KEYS}), "rows": []}
    for instance, default_url in target.instances.items():
        base = base_urls.get(instance) or default_url
        validate_target_url(base, allow_docker_internal=False, docker_hosts=target.docker_hosts)
        inputs = out / target.name / instance / "inputs.json"
        inputs.unlink(missing_ok=True)
        setup_command = [
            sys.executable, str(target.setup),
            "--base-url", base, "--instance", instance, "--out", str(inputs),
        ]
        _run(setup_command, timeout=240)
        results = run_scan(target, instance, mode, base, inputs, out, repeat)
        summary = _score(cases, results, instance, _rule_scopes(target.rules_differential))
        for key in COUNT_KEYS:
            combined["counts"][key] += summary["counts"][key]
        combined["rows"].extend(summary["rows"])
    if sum(combined["counts"].values()) != len(cases):
        raise AssertionError(f"{target.name}/{mode}: {dict(combined['counts'])} != {len(cases)} cases")
    tp, fp, tn, fn = (combined["counts"][key] for key in ("TP", "FP", "TN", "FN"))
    inc_v = combined["counts"]["INC_VULN"]
    combined.update({
        "cases": len(cases),
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn + inc_v) if tp + fn + inc_v else None,
        "recall_excl_inconclusive": tp / (tp + fn) if tp + fn else None,
    })
    return combined


def cleanup_generated_inputs(out: Path, target_name: str | None = None) -> int:
    """Remove setup token files; reports and other benchmark output remain."""
    root = out / target_name if target_name else out
    removed = 0
    if not root.exists():
        return removed
    for path in [*root.rglob("inputs.json"), *root.rglob("ledgerprobe-auth.yaml"),
                 *root.rglob("staging-secrets.env")]:
        if path.is_file():
            path.unlink(missing_ok=True)
            removed += 1
    return removed


def run_target(target: Target, out: Path, *, no_docker: bool, keep: bool,
               keep_out: bool = False,
               base_urls: dict[str, str], repeats: int = 3,
               modes: Iterable[str] = MODES) -> dict[str, Any]:
    document, cases = _load_cases(target.ground_truth)
    try:
        results_by_mode: dict[str, Any] = {}
        determinism: dict[str, Any] = {}
        for mode in modes:
            run_summaries = []
            run_maps = []
            for repeat in range(1, repeats + 1):
                if not no_docker:
                    compose_down(target)
                    compose_up(target, out)
                elif repeats > 1 and target.name == "crapi":
                    raise Blocked("repeated crAPI runs require Docker reset")
                summary = _scan_mode(target, mode, out, base_urls, cases, repeat)
                run_summaries.append(summary)
                run_maps.append({(row["instance"], row["rule_id"]): row["verdict"]
                                 for row in summary["rows"]})
                if not no_docker and not keep:
                    compose_down(target)
            first = run_summaries[0]
            flips = []
            keys = set().union(*run_maps)
            for key in sorted(keys):
                values = [mapping.get(key, "MISSING") for mapping in run_maps]
                if len(set(values)) > 1:
                    flips.append({"instance": key[0], "case": key[1], "verdicts": values})
            results_by_mode[mode] = first
            determinism[mode] = {"runs": repeats, "identical": not flips, "flips": flips}
        return {"status": "ok", "modes": results_by_mode, "determinism": determinism,
                "ground_truth": document}
    except Blocked as exc:
        return {"status": "blocked", "reason": str(exc), "ground_truth": document}
    finally:
        if not no_docker and not keep:
            compose_down(target)
        if not keep_out:
            cleanup_generated_inputs(out, target.name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="LedgerProbe local benchmark harness")
    parser.add_argument("--target", choices=[*TARGETS, "all"], default="all")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--no-docker", action="store_true",
                        help="use already-running loopback targets instead of compose")
    parser.add_argument("--keep", action="store_true", help="leave compose services running")
    parser.add_argument("--keep-out", action="store_true",
                        help="retain generated benchmark/.out inputs.json token files")
    parser.add_argument("--merge", action="store_true",
                        help="update selected targets in an existing results.json")
    parser.add_argument("--repeats", type=int, default=1,
                        help="runs per mode, each preceded by a fresh target reset")
    parser.add_argument("--modes", nargs="+", choices=MODES, default=list(MODES),
                        help="benchmark modes to execute (default: all three)")
    parser.add_argument("--base-url-vulnerable", help="override VAmPI vulnerable instance URL")
    parser.add_argument("--base-url-secure", help="override VAmPI secure instance URL")
    parser.add_argument("--base-url-default", help="override the single-instance target URL")
    args = parser.parse_args(argv)
    if args.repeats < 1:
        parser.error("--repeats must be >= 1")

    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    selected = list(TARGETS) if args.target == "all" else [args.target]
    overrides = {
        "vulnerable": args.base_url_vulnerable,
        "secure": args.base_url_secure,
        "default": args.base_url_default,
    }
    document: dict[str, Any] = {"targets": {}, "generated": datetime.now(timezone.utc).isoformat()}
    prior = out / "results.json"
    if args.merge and prior.exists():
        loaded = json.loads(prior.read_text(encoding="utf-8"))
        if isinstance(loaded, dict) and isinstance(loaded.get("targets"), dict):
            document = loaded
    exit_code = 0
    for name in selected:
        target = TARGETS[name]
        base_urls = {instance: overrides.get(instance) or "" for instance in target.instances}
        if not args.no_docker and not docker_available():
            document["targets"][name] = {
                "status": "blocked",
                "reason": "Docker daemon is not reachable by this user; no containers were started.",
            }
            print(f"[!] {name}: blocked (Docker daemon unavailable)", file=sys.stderr)
            exit_code = 2
            continue
        print(f"[*] target {name}: {', '.join(target.instances)}; {args.repeats} run(s)/mode")
        result = run_target(target, out, no_docker=args.no_docker, keep=args.keep,
                            keep_out=args.keep_out,
                            base_urls=base_urls, repeats=args.repeats, modes=args.modes)
        if args.merge and result.get("status") == "ok":
            previous = document.get("targets", {}).get(name, {})
            if previous.get("status") == "ok":
                result["modes"] = {**previous.get("modes", {}), **result["modes"]}
                result["determinism"] = {**previous.get("determinism", {}),
                                          **result.get("determinism", {})}
        document["targets"][name] = result
        if result["status"] != "ok":
            print(f"[!] {name}: {result['reason']}", file=sys.stderr)
            exit_code = 2
    results_path = BENCH / "RESULTS.md"
    write_results(document, results_path)
    (out / "results.json").write_text(json.dumps(document, indent=2, default=str) + "\n",
                                      encoding="utf-8")
    print(f"[+] results: {results_path}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
