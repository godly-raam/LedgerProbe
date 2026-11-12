from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path

import pytest
import yaml

from pkg.dojo import build_export
from pkg.integrations import FakeTracker, ticket_body, ticket_title
from pkg.observability import github_summary, log_event, metrics_text
from pkg.results import build_document
from tests.fixtures.disposable_server import DISPOSABLE_SENTINEL, create_app
from tests.test_corpus import execute_profile
from pkg.rules import load_rules


def snapshots(app):
    state = app.state.disposable
    return (len(state.items), len(state.resources), len(state.users))


def test_disposable_rules_are_idempotent_and_keep_fingerprints(tmp_path: Path):
    for profile in ("disposable_delete_vulnerable", "disposable_delete_fixed"):
        app = create_app(profile=profile, kill_file=tmp_path / profile / "kill")
        before = snapshots(app)
        (tmp_path / profile / "one").mkdir(parents=True)
        (tmp_path / profile / "two").mkdir(parents=True)
        first = asyncio.run(execute_profile(profile, tmp_path / profile / "one", app=app))
        middle = snapshots(app)
        second = asyncio.run(execute_profile(profile, tmp_path / profile / "two", app=app))
        after = snapshots(app)
        assert first[1]["verdict"] == second[1]["verdict"]
        assert first[1]["fingerprint"] == second[1]["fingerprint"]
        assert before == middle == after


def test_fixture_creation_failure_never_sends_the_attack(tmp_path: Path):
    app = create_app(profile="fixture_creation_fails")
    code, result, _, _ = asyncio.run(execute_profile("fixture_creation_fails", tmp_path, app=app))
    assert code == 2
    assert result["reason"] == "fixture_failed"
    assert app.state.disposable.requests == [
        ("POST", "/api/v1/items", "owner"),
        ("GET", "/api/v1/health", "owner"),
    ]


def test_capture_failure_still_runs_cleanup(tmp_path: Path):
    app = create_app(profile="capture_missing")
    code, result, _, _ = asyncio.run(execute_profile("capture_missing", tmp_path, app=app))
    assert code == 2
    assert result["reason"] == "capture_failed"
    assert ("GET", "/api/v1/health", "owner") in app.state.disposable.requests


def test_cleanup_failure_runs_later_steps_and_exits_two(tmp_path: Path):
    app = create_app(profile="cleanup_failure")
    code, result, _, _ = asyncio.run(execute_profile("cleanup_failure", tmp_path, app=app))
    assert code == 2
    assert result["reason"] == "cleanup_failed"
    paths = [path for _, path, _ in app.state.disposable.requests]
    assert paths[-1] == "/api/v1/health"


def test_kill_switch_stops_attack_but_cleanup_runs(tmp_path: Path):
    kill = tmp_path / "kill"
    app = create_app(profile="kill_switch_during_attack", kill_file=kill)
    code, result, _, _ = asyncio.run(execute_profile("kill_switch_during_attack", tmp_path, app=app))
    assert code == 4
    assert result["reason"] == "kill_switch"
    assert kill.exists()
    deletes = [entry for entry in app.state.disposable.requests if entry[0] == "DELETE"]
    assert len(deletes) == 1  # the attack never ran; this is cleanup
    assert snapshots(app)[0] == 1


def test_every_mutation_gate_sends_no_fixture_traffic(tmp_path: Path):
    for profile in ("blocked_without_allow_mutations", "blocked_host",
                    "blocked_production", "blocked_read_only"):
        app = create_app(profile=profile)
        (tmp_path / profile).mkdir(parents=True)
        code, result, _, _ = asyncio.run(execute_profile(profile, tmp_path / profile, app=app))
        assert code == 2
        assert result["verdict"] == "SKIPPED"
        assert app.state.disposable.requests == []


def test_captured_and_generated_values_never_reach_report_surfaces(tmp_path: Path):
    app = create_app(profile="disposable_delete_vulnerable")
    code, result, sarif_path, junit_path = asyncio.run(
        execute_profile("disposable_delete_vulnerable", tmp_path, app=app))
    assert code == 1
    document = build_document([result], target="http://disposable.test",
                              modes={"read_only": False, "allow_mutations": True,
                                     "spec_check": "strict"},
                              timestamp="2026-11-10T00:00:00+00:00")
    log_stream = io.StringIO()
    log_event("run", "check", target="disposable.test", tool_version="test",
              result=result, stream=log_stream)
    tracker = FakeTracker()
    tracker_ticket = asyncio.run(tracker.create({
        **result,
        "ticket_title": ticket_title(result),
        "ticket_body": ticket_body(result, target="http://disposable.test",
                                   fingerprint=result["fingerprint"], ci_url=None),
        "ticket_labels": [],
        "ticket_metadata": {},
    }))
    surfaces = {
        "result": json.dumps(result),
        "document": json.dumps(document),
        "sarif": sarif_path.read_text(encoding="utf-8"),
        "junit": junit_path.read_text(encoding="utf-8"),
        "defectdojo": json.dumps(build_export([result], target="http://disposable.test")),
        "ticket": ticket_body(result, target="http://disposable.test",
                              fingerprint=result["fingerprint"], ci_url=None),
        "fake_tracker_ticket": tracker_ticket.description,
        "json_log": log_stream.getvalue(),
        "metrics": metrics_text([result], duration_seconds=1.0),
        "summary": github_summary(document),
    }
    for surface, text in surfaces.items():
        assert DISPOSABLE_SENTINEL not in text, surface


def _rule(**overrides):
    rule = {
        "id": "fixture-unit", "name": "Fixture unit", "severity": "high",
        "owasp_category": "API1:2023", "cvss_score": 5.0,
        "target_endpoints": [{"path": "/api/v1/items/{id}", "method": "DELETE"}],
        "auth_contexts": {"primary": "owner", "forbidden": "user"},
        "mutating": True,
        "capture": [{"name": "id", "from": "json", "path": "id"}],
        "verify": {"mode": "probe", "request": {"method": "GET", "path": "/api/v1/items/{{fixture.id}}"},
                   "expected_status": 404},
        "fixture": {"cleanup": [{"identity": "owner", "when_defined": "fixture.id",
                                  "request": {"method": "DELETE", "path": "/api/v1/items/{{fixture.id}}"}}]},
    }
    rule.update(overrides)
    return rule


def _load(tmp_path: Path, rule: dict):
    path = tmp_path / "rule.yaml"
    path.write_text(yaml.safe_dump(rule), encoding="utf-8")
    return load_rules([str(path)])


def test_fixture_cleanup_satisfies_restore_only_without_a_restore_block(tmp_path: Path):
    assert _load(tmp_path, _rule())[0]["id"] == "fixture-unit"


def test_fixture_schema_is_strict(tmp_path: Path):
    bad = _rule()
    bad["fixture"]["cleanup"][0]["unknown"] = True
    with pytest.raises(ValueError, match="unknown rule fields"):
        _load(tmp_path, bad)

    bad = _rule()
    bad["fixture"]["cleanup"][0]["when_defined"] = "fixture.missing"
    with pytest.raises(ValueError, match="declared capture"):
        _load(tmp_path, bad)

    bad = _rule()
    bad["variables"] = {"generated": [{"name": "name", "pattern": "bad-{rand8}"}]}
    with pytest.raises(ValueError, match="start with lp_"):
        _load(tmp_path, bad)
