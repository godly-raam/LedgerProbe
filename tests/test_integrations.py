"""Tracker lifecycle and request-shape tests; MockTransport only, no live services."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import yaml

from pkg.integrations import (
    FakeTracker, JiraTracker, LinearTracker, TrackerError, finding_metadata,
    fingerprint_label, label_set, load_integrations, process_tickets, target_slug,
    ticket_body, ticket_draft,
)
from pkg.fingerprints import fingerprint


NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)


def config(tmp_path: Path, provider: str = "jira", **overrides):
    tracker = {
        "provider": provider, "target_label": "staging", "token_env": "LP_TRACKER_TOKEN",
        "labels": ["security"], "components": ["api"], "assignee": "alice",
        "max_new_tickets_per_run": 20, "max_api_calls": 100,
        "comment_cooldown_days": 7, "auto_close": False,
    }
    if provider == "jira":
        tracker.update({"base_url": "https://jira.test", "project": "SEC"})
    else:
        tracker.update({"endpoint": "https://linear.test/graphql", "team_id": "team-1",
                        "state_open_id": "open-state", "state_resolved_id": "done-state"})
    tracker.update(overrides)
    path = tmp_path / "integrations.yaml"
    path.write_text(yaml.safe_dump({
        "schema_version": "ledgerprobe-integrations/1",
        "tracker": tracker,
        "slack": {"webhook_url_env": "LP_SLACK_WEBHOOK"},
    }, sort_keys=False))
    return load_integrations(path)


def finding(fp: str | None = None, *, status: str = "failed", rule_id: str = "ownership",
            **changes):
    fp = fp or fingerprint(rule_id=rule_id, method="GET", path_template="/objects/{object_id}",
                           identity_roles=["other", "owner"], check_type="bola")
    value = {
        "fingerprint": fp, "rule_id": rule_id, "name": "Object isolation",
        "severity": "high", "owasp_category": "API1:2023", "cvss_score": 8.1,
        "path": "/objects/{object_id}", "path_template": "/objects/{object_id}",
        "method": "GET", "check_type": "bola", "identity_roles": ["other", "owner"],
        "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                 "score": 8.1, "rating": "high"},
        "verdict": {"failed": "FAIL", "passed": "PASS", "suppressed": "FAIL",
                    "inconclusive": "INCONCLUSIVE", "error": "ERROR"}.get(status, "PASS"),
        "status": status, "confidence": "high", "reason": "leak_detected",
        "evidence": {"confirm_runs": 2, "overlap_count": 3},
    }
    value.update(changes)
    return value


def run(results, cfg, tracker=None, *, mode="apply", now=NOW, **kwargs):
    return asyncio.run(process_tickets(results, config=cfg, target="staging", mode=mode,
                                       tracker=tracker, now=now, **kwargs))


def test_first_run_creates_and_identical_second_run_noops():
    tracker = FakeTracker(now=NOW)
    cfg = config(Path("/tmp"))
    first = run([finding()], cfg, tracker)
    assert first.counts["new"] == 1
    assert len(tracker.tickets) == 1
    second = run([finding()], cfg, tracker, now=NOW + timedelta(hours=1))
    assert second.counts["new"] == 0
    assert second.actions == [{"kind": "noop", "fingerprint": finding()["fingerprint"],
                              "rule_id": "ownership", "ticket": "FAKE-1"}]


def test_evidence_change_comments_once_then_cooldown_blocks_second_comment():
    tracker = FakeTracker(now=NOW)
    cfg = config(Path("/tmp"))
    run([finding()], cfg, tracker)
    changed = finding(evidence={"confirm_runs": 3, "overlap_count": 9})
    run([changed], cfg, tracker, now=NOW + timedelta(days=1))
    assert len(tracker.tickets["FAKE-1"].comments) == 1
    run([finding(evidence={"confirm_runs": 4, "overlap_count": 10})], cfg, tracker,
        now=NOW + timedelta(days=2))
    assert len(tracker.tickets["FAKE-1"].comments) == 1


def test_closed_ticket_reappearing_fail_reopens_and_labels_regression():
    tracker = FakeTracker(now=NOW)
    cfg = config(Path("/tmp"))
    draft = ticket_draft(finding(), target="staging", fingerprint=finding()["fingerprint"],
                         ci_url=None, config=cfg.tracker)
    ticket = tracker.seed(draft, state="closed")
    result = run([finding()], cfg, tracker, now=NOW + timedelta(days=1))
    assert result.counts["regressed"] == 1
    assert ticket.state == "open" and "lp-regression" in ticket.labels
    assert any("ledgerprobe-regression" in c.body for c in ticket.comments)


def test_explicit_pass_comments_without_close_then_two_runs_auto_close():
    tracker = FakeTracker(now=NOW)
    cfg = config(Path("/tmp"), auto_close=True)
    draft = ticket_draft(finding(), target="staging", fingerprint=finding()["fingerprint"],
                         ci_url=None, config=cfg.tracker)
    ticket = tracker.seed(draft)
    first = run([finding(status="passed")], cfg, tracker, now=NOW)
    assert first.counts["resolved"] == 0 and ticket.open
    assert any("ledgerprobe-retest-passed" in c.body for c in ticket.comments)
    assert "lp-retest-passed" in ticket.labels
    second = run([finding(status="passed")], cfg, tracker, now=NOW + timedelta(hours=1))
    assert second.counts["resolved"] == 1 and not ticket.open
    assert len([c for c in ticket.comments if "retest-passed" in c.body]) == 2


def test_inconclusive_error_and_absence_do_not_progress_or_create():
    tracker = FakeTracker(now=NOW)
    cfg = config(Path("/tmp"))
    result = run([finding(status="inconclusive"), finding(rule_id="other", status="error")],
                 cfg, tracker)
    assert tracker.tickets == {}
    assert result.counts["new"] == 0
    assert result.counts["inconclusive"] == 1 and result.counts["errors"] == 1


def test_inconclusive_does_not_resolve_an_open_ticket():
    tracker = FakeTracker(now=NOW)
    cfg = config(Path("/tmp"), auto_close=True)
    draft = ticket_draft(finding(), target="staging", fingerprint=finding()["fingerprint"],
                         ci_url=None, config=cfg.tracker)
    ticket = tracker.seed(draft)
    result = run([finding(status="inconclusive")], cfg, tracker)
    assert ticket.open and result.counts["resolved"] == 0
    assert ticket.comments == []


def test_suppressed_does_not_create_and_comments_existing_ticket_once():
    tracker = FakeTracker(now=NOW)
    cfg = config(Path("/tmp"))
    draft = ticket_draft(finding(), target="staging", fingerprint=finding()["fingerprint"],
                         ci_url=None, config=cfg.tracker)
    ticket = tracker.seed(draft)
    suppressed = finding(status="suppressed",
                         suppression={"expires": "2026-12-01", "owner": "security"})
    first = run([suppressed], cfg, tracker)
    second = run([suppressed], cfg, tracker, now=NOW + timedelta(days=1))
    assert first.counts["suppressed"] == 1 and second.counts["suppressed"] == 1
    assert len([c for c in ticket.comments if "ledgerprobe-suppressed" in c.body]) == 1


def test_suppressed_without_a_ticket_never_creates_one():
    tracker = FakeTracker(now=NOW)
    cfg = config(Path("/tmp"))
    result = run([finding(status="suppressed", suppression={"expires": "2026-12-01"})], cfg,
                 tracker)
    assert tracker.tickets == {}
    assert result.counts["new"] == 0 and result.counts["suppressed"] == 1


def test_flood_cap_creates_summary_ticket_and_warning():
    tracker = FakeTracker(now=NOW)
    cfg = config(Path("/tmp"), max_new_tickets_per_run=2)
    rows = [finding(rule_id=f"r{i}") for i in range(4)]
    result = run(rows, cfg, tracker)
    assert result.counts["new"] == 3
    assert len(tracker.tickets) == 3
    assert any("New-ticket flood summary" in t.title for t in tracker.tickets.values())
    assert any(item.startswith("new_ticket_cap:") for item in result.warnings)


def test_duplicate_tickets_keep_oldest_and_label_newer():
    tracker = FakeTracker(now=NOW)
    cfg = config(Path("/tmp"))
    draft = ticket_draft(finding(), target="staging", fingerprint=finding()["fingerprint"],
                         ci_url=None, config=cfg.tracker)
    old = tracker.seed(draft, created_at=NOW - timedelta(days=2))
    new = tracker.seed(draft, created_at=NOW - timedelta(days=1))
    result = run([finding()], cfg, tracker)
    assert old.key != new.key and "lp-duplicate" in new.labels
    assert any(old.key in c.body for c in new.comments)
    assert "duplicate_ticket:" in " ".join(result.warnings)


def test_same_fingerprint_two_targets_creates_two_tickets():
    tracker = FakeTracker(now=NOW)
    cfg = config(Path("/tmp"))
    run([finding()], cfg, tracker)
    other = config(Path("/tmp"), target_label="production")
    run([finding()], other, tracker, now=NOW + timedelta(minutes=1))
    assert len(tracker.tickets) == 2
    assert {target_slug("staging"), target_slug("production")} <= {
        label for ticket in tracker.tickets.values() for label in ticket.labels}


def test_body_contains_only_allowlisted_evidence_and_no_secret_values():
    result = finding(path="/objects/object-SECRET-123?token=SECRET-TOKEN",
                     path_template="/objects/{object_id}",
                     evidence={"confirm_runs": 2, "overlap_count": 3,
                               "shape_hashes": {"primary": "a" * 64, "body": "SECRET-BODY"},
                               "object_id": "SECRET-OBJECT", "token": "SECRET-TOKEN"},
                     name="Object isolation SECRET-MARKER")
    body = ticket_body(result, target="staging", fingerprint=result["fingerprint"], ci_url=None)
    for secret in ("SECRET-TOKEN", "SECRET-BODY", "SECRET-OBJECT", "SECRET-MARKER", "object-SECRET-123"):
        assert secret not in body
    assert "ledgerprobe-fingerprint:" in body
    assert "shape_hashes" in body


@pytest.mark.parametrize("status", ["failed", "passed", "suppressed", "inconclusive", "error", "skipped"])
def test_every_verdict_body_is_safe(status):
    result = finding(status=status,
                     path="/objects/object-SECRET-ID?token=SECRET-TOKEN",
                     name="Object SECRET-NAME", message="SECRET message",
                     response_body="SECRET response",
                     canary="canary-vampi-SECRET", balance="SECRET balance",
                     evidence={"confirm_runs": 2, "overlap_count": 3,
                               "object_id": "SECRET-ID", "token": "SECRET-TOKEN",
                               "response": "SECRET response",
                               "shape_hashes": {"primary": "a" * 64, "body": "SECRET"}},
                     remediation="Rotate the object authorization check.")
    body = ticket_body(result, target="staging", fingerprint=result["fingerprint"], ci_url=None)
    for secret in ("SECRET-ID", "SECRET-TOKEN", "SECRET-NAME", "SECRET message",
                   "SECRET response", "canary-vampi", "SECRET balance", "Bearer"):
        assert secret not in body
    assert "ledgerprobe-fingerprint:" in body
    assert "remediation: Rotate" in body
    assert "[redacted]" in body or "SECRET" not in body


def test_retest_marker_is_counted_and_label_is_added():
    tracker = FakeTracker(now=NOW)
    cfg = config(Path("/tmp"))
    draft = ticket_draft(finding(), target="staging", fingerprint=finding()["fingerprint"],
                         ci_url=None, config=cfg.tracker)
    ticket = tracker.seed(draft)
    run([finding(status="passed")], cfg, tracker)
    assert "lp-retest-passed" in ticket.labels


def test_dry_run_prints_three_creates_and_does_not_use_network(capsys):
    cfg = config(Path("/tmp"))
    rows = [finding(rule_id=f"rule{i}") for i in range(3)]
    result = run(rows, cfg, None, mode="dry-run")
    output = capsys.readouterr().out
    assert result.counts["new"] == 3
    assert output.count("[tickets] create ") == 3
    assert "https://" not in output


def test_jira_request_shapes_and_auth_header(monkeypatch):
    monkeypatch.setenv("LP_TRACKER_TOKEN", "token-value")
    monkeypatch.setenv("LP_TRACKER_EMAIL", "owner@example.test")
    cfg = config(Path("/tmp"), email_env="LP_TRACKER_EMAIL")
    seen = []
    def handler(request):
        seen.append(request)
        if request.method == "GET" and request.url.path.endswith("/search"):
            return httpx.Response(200, json={"issues": []})
        if request.method == "POST" and request.url.path.endswith("/issue"):
            return httpx.Response(201, json={"key": "SEC-9", "self": "https://jira.test/browse/SEC-9"})
        if request.method == "POST" and request.url.path.endswith("/comment"):
            return httpx.Response(201, json={"id": "1", "created": "2026-11-03T12:00:00Z"})
        return httpx.Response(404)
    tracker = JiraTracker(cfg.tracker, "token-value", transport=httpx.MockTransport(handler), now=NOW)
    draft = ticket_draft(finding(), target="staging", fingerprint=finding()["fingerprint"],
                         ci_url=None, config=cfg.tracker)
    assert asyncio.run(tracker.find_all(draft["fingerprint"], "staging")) == []
    ticket = asyncio.run(tracker.create(draft))
    asyncio.run(tracker.comment(ticket, "ledgerprobe-retest-passed: run x"))
    assert ticket.key == "SEC-9"
    assert seen[0].headers["Authorization"].startswith("Basic ")
    search = seen[0]
    assert search.url.params["jql"].count("labels =") == 2
    created_request = next(item for item in seen if item.method == "POST"
                           and item.url.path.endswith("/issue"))
    created = json.loads(created_request.content)["fields"]
    assert created["project"] == {"key": "SEC"}
    assert created["labels"][0].startswith("lp-")
    assert "ledgerprobe-fingerprint:" in created["description"]["content"][0]["content"][0]["text"]
    assert any(item.url.path.endswith("/issue/SEC-9/comment") for item in seen)


def test_linear_request_shapes_and_auth_header(monkeypatch):
    monkeypatch.setenv("LP_TRACKER_TOKEN", "lin-token")
    fp = finding()["fingerprint"]
    labels = label_set(fp, "staging", ["security"])
    cfg = config(Path("/tmp"), provider="linear",
                 label_ids={name: f"id-{i}" for i, name in enumerate(labels)})
    seen = []
    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"data": {
            "issues": {"nodes": []},
            "issueCreate": {"success": True, "issue": {
                "id": "issue-id", "identifier": "LIN-1", "url": "https://linear.test/LIN-1"}},
            "commentCreate": {"success": True, "comment": {"id": "c1", "body": "x",
                                                               "createdAt": "2026-11-03T12:00:00Z"}},
        }})
    tracker = LinearTracker(cfg.tracker, "lin-token", transport=httpx.MockTransport(handler), now=NOW)
    draft = ticket_draft(finding(), target="staging", fingerprint=fp, ci_url=None, config=cfg.tracker)
    asyncio.run(tracker.find_all(fp, "staging"))
    ticket = asyncio.run(tracker.create(draft))
    asyncio.run(tracker.comment(ticket, "ledgerprobe-retest-passed: run x"))
    assert seen[0].headers["Authorization"] == "lin-token"
    first = json.loads(seen[0].content)
    assert "issues(filter" in first["query"]
    create_request = next(item for item in seen
                          if "issueCreate" in json.loads(item.content).get("query", ""))
    second = json.loads(create_request.content)
    assert "issueCreate" in second["query"]
    assert second["variables"]["input"]["teamId"] == "team-1"
    assert second["variables"]["input"]["title"].startswith("[LedgerProbe]")
    assert second["variables"]["input"]["description"].startswith("ledgerprobe-fingerprint:")
    assert len(second["variables"]["input"]["labelIds"]) == len(labels)
    comment_request = next(item for item in seen
                           if "commentCreate" in json.loads(item.content).get("query", ""))
    third = json.loads(comment_request.content)
    assert third["variables"]["input"]["issueId"] == "issue-id"


def test_429_retry_after_retries_then_succeeds(monkeypatch):
    monkeypatch.setenv("LP_TRACKER_TOKEN", "token")
    cfg = config(Path("/tmp"))
    calls, sleeps = [], []
    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(429, headers={"retry-after": "0"})
        return httpx.Response(200, json={"issues": []})
    async def sleep(value):
        sleeps.append(value)
    tracker = JiraTracker(cfg.tracker, "token", transport=httpx.MockTransport(handler), sleep=sleep, now=NOW)
    assert asyncio.run(tracker.find_all(finding()["fingerprint"], "staging")) == []
    assert len(calls) == 3 and sleeps == [0.0]


def test_any_5xx_is_retried_and_api_cap_is_enforced(monkeypatch):
    monkeypatch.setenv("LP_TRACKER_TOKEN", "token")
    cfg = config(Path("/tmp"), retry_attempts=1, max_api_calls=3)
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(502)
    tracker = JiraTracker(cfg.tracker, "token", transport=httpx.MockTransport(handler),
                          sleep=lambda value: asyncio.sleep(0), now=NOW)
    with pytest.raises(TrackerError):
        asyncio.run(tracker.find_all(finding()["fingerprint"], "staging"))
    assert len(calls) == 2
    tracker.calls = 3
    with pytest.raises(TrackerError, match="cap reached"):
        asyncio.run(tracker.find_all(finding()["fingerprint"], "staging"))


def test_persistent_5xx_is_sanitized_tracker_error_and_results_are_unchanged(monkeypatch):
    monkeypatch.setenv("LP_TRACKER_TOKEN", "token")
    cfg = config(Path("/tmp"), retry_attempts=0)
    def handler(request):
        raise httpx.ConnectError("SECRET URL", request=request)
    tracker = JiraTracker(cfg.tracker, "token", transport=httpx.MockTransport(handler), now=NOW)
    original = finding()
    result = run([original], cfg, tracker)
    assert result.errors and "SECRET" not in " ".join(result.errors)
    assert original["status"] == "failed"


def test_config_rejects_inline_credentials_unknown_fields_and_url_credentials(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump({"schema_version": "ledgerprobe-integrations/1", "tracker": {
        "provider": "jira", "base_url": "https://user:pass@jira.test", "project": "SEC",
        "token_env": "Bearer abcdefghijklmnop", "target_label": "staging",
    }}))
    with pytest.raises(ValueError):
        load_integrations(path)
    path.write_text(yaml.safe_dump({"schema_version": "ledgerprobe-integrations/1", "tracker": {
        "provider": "jira", "base_url": "https://jira.test", "project": "SEC",
        "token_env": "TOKEN", "target_label": "staging", "token": "inline",
    }}))
    with pytest.raises(ValueError):
        load_integrations(path)


def test_slack_digest_is_one_message_with_counts_and_links(monkeypatch):
    monkeypatch.setenv("LP_TRACKER_TOKEN", "token")
    monkeypatch.setenv("LP_SLACK_WEBHOOK", "https://hooks.slack.test/services/x")
    cfg = config(Path("/tmp"))
    tracker = FakeTracker(now=NOW)
    seen = []
    slack = httpx.MockTransport(lambda request: (seen.append(request), httpx.Response(200))[1])
    result = run([finding(status="passed"), finding(rule_id="inc", status="inconclusive")],
                 cfg, tracker, slack_transport=slack)
    assert len(seen) == 1
    text = json.loads(seen[0].content)["text"]
    assert "new=0" in text and "inconclusive=1" in text
    assert "evidence" not in text
    assert result.slack_text == text