from __future__ import annotations

import os
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "run-action.sh"


def _run(tmp_path, exit_code):
    tmp_path.mkdir(parents=True, exist_ok=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "ledgerprobe"
    stub.write_text(f"#!/bin/sh\nexit {exit_code}\n")
    stub.chmod(0o755)
    output = tmp_path / "github-output"
    output.write_text("")
    env = {
        **os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "GITHUB_OUTPUT": str(output), "INPUT_SPEC": "spec.json",
        "INPUT_RULES": "rules.json", "INPUT_AUTH": "", "INPUT_BASELINE": "",
        "INPUT_FAIL_ON": "new", "INPUT_TICKETS": "plan",
        "INPUT_ENVIRONMENT": "staging",
    }
    result = subprocess.run(["bash", str(SCRIPT)], env=env, cwd=tmp_path,
                            capture_output=True, text=True)
    return result.returncode, output.read_text()


def test_action_script_writes_outputs_before_propagating_exit_code(tmp_path):
    for code in (0, 1, 2):
        returncode, output = _run(tmp_path / str(code), code)
        assert returncode == code
        assert "sarif=" in output
        assert "junit=" in output
        assert "results=" in output


def test_action_yaml_uses_the_script_and_guards_followup_steps():
    document = yaml.safe_load((ROOT / "action.yml").read_text())
    steps = document["runs"]["steps"]
    scan = next(step for step in steps if step.get("id") == "scan")
    assert "scripts/run-action.sh" in scan["run"]
    summary = next(step for step in steps if step.get("name") == "Write step summary")
    upload = next(step for step in steps if step.get("name") == "Upload SARIF")
    assert "always()" in summary["if"] and "hashFiles" in summary["if"]
    assert "always()" in upload["if"] and "hashFiles" in upload["if"]