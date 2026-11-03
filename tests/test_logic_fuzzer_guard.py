from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
MAIN = ROOT / "logic-fuzzer" / "main.py"


def _run(*args):
    return subprocess.run([sys.executable, str(MAIN), *args], cwd=ROOT,
                          capture_output=True, text=True, timeout=10)


def test_legacy_fuzzer_requires_explicit_mutation_acknowledgement():
    result = _run("--base-url", "http://127.0.0.1:1", "--suites", "race")
    assert result.returncode == 2
    assert "--allow-mutations" in result.stdout


def test_legacy_fuzzer_refuses_non_loopback_even_with_acknowledgement():
    result = _run("--base-url", "http://example.com", "--allow-mutations", "--suites", "race")
    assert result.returncode == 2
    assert "loopback" in result.stdout
