"""Reporter tests use local files and MockTransport only; no live webhooks."""

import asyncio
import copy
import inspect
import json
from pathlib import Path
from xml.etree import ElementTree as ET

import httpx
import pytest

from pkg.guardrails import GuardedClient
from pkg.reporter import notify, write_junit, write_sarif
from pkg.reporter.sarif import write_sarif as sarif_writer


def result(**changes):
    value = {
        "rule_id": "ownership", "name": "Object authorization", "severity": "high",
        "owasp_category": "API1:2023", "cvss_score": 8.1,
        "path": "/items/{id}", "method": "GET", "status": "failed",
        "message": "Authorization check failed",
        "assertions": [{"type": "status_code", "passed": False}],
    }
    value.update(changes)
    return value


def test_sarif_metadata_locations_and_statuses(tmp_path):
    rows = [result(), result(path="/accounts/{id}", method="POST"),
            result(status="passed"), result(status="skipped"),
            result(status="error", message="Check could not run")]
    original = copy.deepcopy(rows)
    path = tmp_path / "report.sarif"
    assert sarif_writer is write_sarif
    assert write_sarif(iter(rows), str(path)) == path
    document = json.loads(path.read_text())
    assert document["version"] == "2.1.0"
    assert document["$schema"].endswith("sarif-2.1.0.json")
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "LedgerProbe"
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "ownership"
    assert rules[0]["name"] == "Object authorization"
    assert rules[0]["shortDescription"]["text"]
    assert rules[0]["properties"]["security-severity"] == "8.1"
    assert "security" in rules[0]["properties"]["tags"]
    assert "owasp/API1:2023" in rules[0]["properties"]["tags"]
    assert len(run["results"]) == 2
    for finding, endpoint in zip(run["results"], ("GET /items/{id}", "POST /accounts/{id}")):
        assert finding["ruleId"] == "ownership"
        assert finding["ruleIndex"] == 0
        assert finding["level"] == "error"
        assert finding["locations"] == [{"logicalLocations": [{"fullyQualifiedName": endpoint}]}]
        assert set(finding["partialFingerprints"]) == {"ledgerprobe/v1"}
        assert len(finding["partialFingerprints"]["ledgerprobe/v1"]) == 64
    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert invocation["toolExecutionNotifications"] == [{
        "associatedRule": {"id": "ownership", "index": 0}, "level": "error",
        "message": {"text": "Check could not run"},
    }]
    assert rows == original


@pytest.mark.parametrize("severity,level", [
    ("critical", "error"), ("high", "error"), ("medium", "warning"),
    ("low", "note"), ("info", "note"),
])
def test_sarif_severity_and_rule_indexes(tmp_path, severity, level):
    path = tmp_path / "report.json"
    write_sarif([result(status="passed"), result(rule_id="second", severity=severity)], path)
    run = json.loads(path.read_text())["runs"][0]
    finding = run["results"][0]
    assert finding["ruleIndex"] == 1
    assert run["tool"]["driver"]["rules"][finding["ruleIndex"]]["id"] == finding["ruleId"]
    assert finding["level"] == level


def test_sarif_fingerprint_stable_across_order_message_and_status(tmp_path):
    path = tmp_path / "report.json"
    def fingerprints(rows):
        write_sarif(rows, path)
        return {r["ruleId"]: r["partialFingerprints"] for r in json.loads(path.read_text())["runs"][0]["results"]}
    first = fingerprints([result(), result(rule_id="other")])
    second = fingerprints([result(rule_id="other"), result(message="Changed message", severity="critical")])
    assert first == second
    assert first["ownership"] != first["other"]
    assert fingerprints([result(method="POST")])["ownership"] != first["ownership"]
    assert fingerprints([result(path="/other")])["ownership"] != first["ownership"]


@pytest.mark.parametrize("rows", [[], [result(status="passed"), result(status="skipped")]])
def test_sarif_no_findings_is_successful(tmp_path, rows):
    path = tmp_path / "report.json"
    write_sarif(rows, path)
    run = json.loads(path.read_text())["runs"][0]
    assert run["results"] == []
    assert run["invocations"] == [{"executionSuccessful": True, "toolExecutionNotifications": []}]


def test_sarif_error_is_not_security_finding_and_empty_messages_are_valid(tmp_path):
    path = tmp_path / "report.json"
    write_sarif([result(status="error", message="")], path)
    run = json.loads(path.read_text())["runs"][0]
    assert run["results"] == []
    assert run["invocations"][0]["toolExecutionNotifications"][0]["message"]["text"]
    write_sarif([result(message="")], path)
    assert json.loads(path.read_text())["runs"][0]["results"][0]["message"]["text"]


@pytest.mark.parametrize("source_uri", ["examples/bank.openapi.yaml", Path("examples/bank.openapi.yaml")])
def test_sarif_optional_source_preserves_logical_location_and_fingerprint(tmp_path, source_uri):
    path = tmp_path / "report.sarif"
    rows = [result(), result(path="/accounts/{id}", method="POST"), result(status="error")]
    original = copy.deepcopy(rows)
    write_sarif(rows, path)
    logical_only = json.loads(path.read_text())
    assert write_sarif(rows, str(path), source_uri=source_uri) == path
    source_linked = json.loads(path.read_text())
    for linked, logical in zip(source_linked["runs"][0]["results"], logical_only["runs"][0]["results"]):
        assert linked["locations"][0].pop("physicalLocation") == {
            "artifactLocation": {"uri": "examples/bank.openapi.yaml"},
        }
        assert linked == logical
    assert source_linked == logical_only
    assert rows == original


def test_sarif_explicit_none_and_keyword_only_source_uri(tmp_path):
    path = tmp_path / "report.sarif"
    write_sarif([result()], path)
    default = path.read_bytes()
    write_sarif([result()], path, source_uri=None)
    assert path.read_bytes() == default
    with pytest.raises(TypeError):
        inspect.signature(write_sarif).bind([result()], path, "examples/bank.openapi.yaml")


@pytest.mark.parametrize("source_uri", [None, "examples/bank.openapi.yaml"])
def test_sarif_official_schema_when_available(tmp_path, source_uri):
    # Schema is an optional ignored download; tests never fetch it themselves.
    schema_path = Path(__file__).resolve().parents[1] / ".demo" / "sarif-schema.json"
    if not schema_path.is_file():
        pytest.skip("Official SARIF schema has not been downloaded to .demo")
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft7Validator.check_schema(schema)
    validator = jsonschema.Draft7Validator(schema, format_checker=jsonschema.Draft7Validator.FORMAT_CHECKER)
    rows = [result(rule_id=severity, severity=severity)
            for severity in ("critical", "high", "medium", "low", "info")]
    rows += [result(status="passed"), result(status="skipped"), result(status="error")]
    path = tmp_path / "report.sarif"
    write_sarif(rows, path, source_uri=source_uri)
    document = json.loads(path.read_text())
    validator.validate(document)
    assert len(document["runs"][0]["results"]) == 5
    assert document["runs"][0]["invocations"][0]["executionSuccessful"] is False


def test_junit_all_statuses_and_xml_escaping(tmp_path):
    rows = [result(status=s, name='Check <owner> & "reader"', message="Bad <xml> & text\x00")
            for s in ("passed", "failed", "error", "skipped")]
    original = copy.deepcopy(rows)
    path = tmp_path / "junit.xml"
    assert write_junit(iter(rows), str(path)) == path
    suite = ET.parse(path).getroot()
    assert suite.tag == "testsuite"
    assert suite.attrib == {"name": "LedgerProbe", "tests": "4", "failures": "1", "errors": "1", "skipped": "1"}
    cases = suite.findall("testcase")
    assert len(cases) == 4
    assert cases[0].attrib == {"classname": "ownership", "name": 'Check <owner> & "reader" [GET /items/{id}]'}
    assert len(cases[0]) == 0
    for case, tag in zip(cases[1:], ("failure", "error", "skipped")):
        assert len(case) == 1
        assert case[0].tag == tag
        assert case[0].text == "Bad <xml> & text\ufffd"
        assert case[0].get("message") == case[0].text
    assert rows == original


def test_junit_empty(tmp_path):
    path = tmp_path / "junit.xml"
    write_junit([], path)
    suite = ET.parse(path).getroot()
    assert suite.get("tests") == "0"
    assert len(suite) == 0


def test_webhook_payloads_filtering_headers_and_redaction():
    async def scenario():
        seen = []
        def handler(request):
            seen.append(request)
            return httpx.Response(200, json={"data": {"issueCreate": {"success": True}}})
        rows = [result(), result(severity="critical"), result(severity="medium"),
                result(severity="low"), result(severity="info"), result(status="passed"),
                result(status="error"), result(status="skipped")]
        for row in rows:
            row.update(message="SECRET message", assertions=[{"response_body": "SECRET body"}],
                       auth_context={"Authorization": "SECRET auth"}, response_body="SECRET response",
                       path="/items/{id}?token=SECRET-query#SECRET-fragment")
        hooks = [{"kind": kind, "url": "https://notify.test/" + kind,
                  "headers": {"Authorization": "Bearer configured-token"},
                  **({"project": "SEC"} if kind == "jira" else {}),
                  **({"team_id": "team-123"} if kind == "linear" else {})}
                 for kind in ("slack", "teams", "jira", "linear", "generic")]
        original = copy.deepcopy((rows, hooks))
        async with GuardedClient(max_rps=1e9, transport=httpx.MockTransport(handler)) as client:
            assert await notify(iter(rows), hooks, client) is None
        assert len(seen) == 10
        for request in seen:
            assert request.method == "POST"
            assert request.headers["Authorization"] == "Bearer configured-token"
            assert b"SECRET" not in request.content
            payload = json.loads(request.content)
            kind = request.url.path[1:]
            if kind in {"slack", "teams"}:
                assert set(payload) == {"text"}
                assert "GET /items/{id}" in payload["text"]
                assert payload["text"].startswith("LedgerProbe ")
            elif kind == "jira":
                fields = payload["fields"]
                assert fields["project"] == {"key": "SEC"}
                assert fields["issuetype"] == {"name": "Task"}
                assert fields["summary"].startswith("LedgerProbe ")
                assert fields["description"]["version"] == 1
                assert fields["description"]["type"] == "doc"
                assert fields["description"]["content"][0]["content"][0]["type"] == "text"
            elif kind == "linear":
                assert "mutation LedgerProbeIssue(" in payload["query"]
                assert "issueCreate(input: $input)" in payload["query"]
                assert "$input: IssueCreateInput!" in payload["query"]
                assert payload["variables"]["input"]["teamId"] == "team-123"
                assert payload["variables"]["input"]["title"].startswith("LedgerProbe ")
                assert set(payload["variables"]["input"]) == {"teamId", "title", "description"}
            else:
                assert payload["event"] == "ledgerprobe.finding"
                assert payload["result"]["path"] == "/items/{id}"
                assert set(payload["result"]) == {
                    "rule_id", "name", "severity", "owasp_category", "cvss_score", "path", "method", "status"}
        assert (rows, hooks) == original
    asyncio.run(scenario())


@pytest.mark.parametrize("url", [
    "http://localhost:8000/hooks", "http://127.0.0.1/hooks", "http://[::1]:8000/hooks",
    "https://notify.test/hooks?token=private",
])
def test_webhook_allowed_urls(url):
    async def scenario():
        seen = []
        async with GuardedClient(max_rps=1e9, transport=httpx.MockTransport(
            lambda r: (seen.append(r), httpx.Response(204))[1]
        )) as client:
            await notify([result()], [{"kind": "generic", "url": url}], client)
        assert len(seen) == 1
    asyncio.run(scenario())


@pytest.mark.parametrize("changes", [
    {"url": "http://notify.test/SECRET"}, {"url": "ftp://notify.test/SECRET"},
    {"url": "file:///SECRET"}, {"url": "/relative/SECRET"},
    {"url": "https://user:SECRET@notify.test"}, {"url": "https://user@notify.test"},
    {"url": "https://notify.test/#SECRET"}, {"url": "https://notify.test/#"},
    {"url": "https://notify.test:bad/SECRET"}, {"url": "https://notify.test:0/SECRET"},
    {"url": "https://notify.test/\nSECRET"}, {"url": "https://notify.test/\\SECRET"},
    {"url": "https://"}, {"url": None}, {"url": 123}, {"url": ""},
    {"url": "http://localhost.evil.test/SECRET"},
    {"kind": "unknown"}, {"kind": []}, {"headers": None},
    {"headers": {"Authorization": "SECRET\r\nInjected: yes"}},
    {"headers": {"Bad Header": "SECRET"}}, {"headers": {"x": 123}},
    {"kind": "jira"}, {"kind": "jira", "project": " "},
    {"kind": "linear"}, {"kind": "linear", "team_id": 123},
])
def test_invalid_webhook_fails_before_any_delivery_even_without_findings(changes):
    async def scenario():
        seen = []
        valid = {"kind": "generic", "url": "https://notify.test/hooks"}
        bad = {**valid, **changes}
        async with GuardedClient(max_rps=1e9, transport=httpx.MockTransport(
            lambda r: (seen.append(r), httpx.Response(200))[1]
        )) as client:
            for rows in ([], [result()]):
                with pytest.raises(ValueError) as error:
                    await notify(rows, [valid, bad], client)
                assert "SECRET" not in str(error.value)
        assert seen == []
    asyncio.run(scenario())


@pytest.mark.parametrize("hooks", [None, {}, "https://notify.test", [None]])
def test_invalid_webhook_list(hooks):
    with pytest.raises(ValueError):
        asyncio.run(notify([], hooks, None))


def test_empty_destinations_and_no_qualifying_findings_do_not_send():
    async def scenario():
        await notify([result()], [], None)
        await notify([result(status="error"), result(severity="medium")],
                     [{"kind": "generic", "url": "https://notify.test"}], None)
    asyncio.run(scenario())


@pytest.mark.parametrize("status", [301, 400, 401, 429, 500])
def test_non_2xx_sanitized_and_never_retried_or_redirected(status):
    async def scenario():
        seen = []
        def handler(request):
            seen.append(request)
            return httpx.Response(status, text="SECRET response", headers={"location": "https://other.test/SECRET"})
        async with GuardedClient(max_rps=1e9, transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(ValueError) as error:
                await notify([result()], [{"kind": "generic", "url": "https://notify.test/SECRET?token=SECRET"}], client)
        assert str(status) in str(error.value)
        assert "SECRET" not in str(error.value)
        assert len(seen) == 1
    asyncio.run(scenario())


def test_transport_error_is_sanitized_and_not_retried():
    async def scenario():
        seen = []
        def handler(request):
            seen.append(request)
            raise httpx.ConnectError("SECRET token URL", request=request)
        async with GuardedClient(max_rps=1e9, transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(ValueError, match="^Webhook delivery failed$") as error:
                await notify([result()], [{"kind": "generic", "url": "https://notify.test/SECRET"}], client)
        assert error.value.__suppress_context__
        assert len(seen) == 1
    asyncio.run(scenario())


@pytest.mark.parametrize("body", [
    {"errors": [{"message": "SECRET"}]},
    {"data": {"issueCreate": {"success": False}}}, {}, [], None,
])
def test_linear_application_errors_are_sanitized(body):
    async def scenario():
        async with GuardedClient(max_rps=1e9, transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json=body)
        )) as client:
            with pytest.raises(ValueError, match="^Linear issue creation failed$"):
                await notify([result()], [{"kind": "linear", "team_id": "team", "url": "https://notify.test/SECRET"}], client)
    asyncio.run(scenario())


def test_notification_client_policy_is_not_bypassed():
    async def scenario():
        seen = []
        transport = httpx.MockTransport(lambda r: (seen.append(r), httpx.Response(204))[1])
        hooks = [{"kind": "generic", "url": "https://notify.test/hooks"}]
        async with GuardedClient(read_only=True, transport=transport) as scan_client:
            with pytest.raises(ValueError, match="^Webhook delivery failed$"):
                await notify([result()], hooks, scan_client)
        assert seen == []
        async with GuardedClient(transport=transport) as notification_client:
            await notify([result()], hooks, notification_client)
        assert len(seen) == 1
    asyncio.run(scenario())
