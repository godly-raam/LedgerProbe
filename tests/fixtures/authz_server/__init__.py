from __future__ import annotations

from pathlib import Path
import yaml

from .app import SEEDED_DATA, create_app
from .transport import TimingOutASGITransport

FIXTURES_DIR = Path(__file__).resolve().parent
EXPECTATIONS_PATH = FIXTURES_DIR / "expectations.yaml"
SPEC_PATH = FIXTURES_DIR / "openapi.json"
INPUTS_PATH = FIXTURES_DIR / "inputs.json"


def load_expectations() -> dict[str, dict]:
    """Load the machine-readable expectations registry."""
    with open(EXPECTATIONS_PATH, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


__all__ = [
    "create_app",
    "TimingOutASGITransport",
    "FIXTURES_DIR",
    "EXPECTATIONS_PATH",
    "SPEC_PATH",
    "INPUTS_PATH",
    "SEEDED_DATA",
    "load_expectations",
]
