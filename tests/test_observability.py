import io
import json
from pathlib import Path

import httpx
import yaml

from pkg.auth import register_secret
from pkg.observability import REQUIRED, github_summary, log_event, metrics_text


def test_json_log_has_required_fields_and_redacts_sentinel():
    sentinel = "LP-SENTINEL-7391528-X"
    register_secret(sentinel)
    stream = io.StringIO()
    record = log_event("run-LP-SENTINEL-7391528-X", "check", target="target.test",
                       tool_version="1.1.0", stream=stream,
                       result={"rule_id": "ownership", "fingerprint": "lp1:" + "a" * 64,
                               "verdict": "FAIL", "reason": sentinel,
                               "path_template": "/objects/{{id}}"},
                       http_status=403)
    line = stream.getvalue()
    assert json.loads(line) == record
    assert set(REQUIRED) <= set(record)
    assert sentinel not in line
    assert "/objects/{{id}}" in line
    assert record["target"] == "target.test"


def test_metrics_and_summary_are_metadata_only():
    results = [
        {"status": "failed", "verdict": "FAIL"},
        {"status": "inconclusive", "verdict": "INCONCLUSIVE"},
    ]
    text = metrics_text(results, duration_seconds=1.25, tracker_errors=2, auth_errors=1)
    assert 'ledgerprobe_verdict_count{verdict="FAIL"} 1' in text
    assert "ledgerprobe_inconclusive_ratio 0.5" in text
    assert "ledgerprobe_tracker_errors_total 2" in text
    summary = github_summary({"summary": {"checks": 2, "failed": 1},
                              "findings": [{"rule_id": "ownership", "fingerprint": "lp1:" + "b" * 64,
                                            "status": "failed", "evidence": {"id": "EXPANDED-SECRET"}}]})
    assert "ownership" in summary and "EXPANDED-SECRET" not in summary


def test_cli_json_and_metrics_are_machine_only(tmp_path, capsys):
    from tests.test_cli import scan
    def handler(request):
        return httpx.Response(200 if request.headers.get("Authorization") == "owner-secret" else 403)
    code, _, _ = scan(tmp_path, handler, extra=(
        "--read-only", "--log-format", "json", "--run-id", "pipeline-42",
        "--metrics-file", str(tmp_path / "metrics.prom")))
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line]
    assert code == 0
    assert all(set(REQUIRED) <= set(line) for line in lines)
    assert any(line["event"] == "run_summary" for line in lines)
    assert all(line["run_id"] == "pipeline-42" for line in lines)
    metrics = (tmp_path / "metrics.prom").read_text()
    assert "ledgerprobe_run_duration_seconds" in metrics


def test_action_and_workflow_yaml_is_valid():
    root = Path(__file__).parents[1]
    for path in [root / "action.yml", *sorted((root / ".github/workflows").glob("*.yml")),
                 *sorted((root / "examples/github-actions").glob("*.yml"))]:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(document, dict), path
