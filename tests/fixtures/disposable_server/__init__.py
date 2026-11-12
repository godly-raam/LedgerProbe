from __future__ import annotations

from pathlib import Path

from .app import DISPOSABLE_SENTINEL, DisposableState, create_app

FIXTURES_DIR = Path(__file__).resolve().parent
SPEC_PATH = FIXTURES_DIR / "openapi.json"
INPUTS_PATH = FIXTURES_DIR / "inputs.json"

__all__ = ["DISPOSABLE_SENTINEL", "DisposableState", "create_app",
           "FIXTURES_DIR", "SPEC_PATH", "INPUTS_PATH"]