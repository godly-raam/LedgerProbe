"""Lab configuration. Toggles turn the intentional vulnerabilities on or off."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[1] / "config.json"


@dataclass(frozen=True)
class Settings:
    enable_bola_bug: bool = True
    enable_race_condition: bool = True
    enable_mcc_pollution_bug: bool = True
    enable_sim_swap_bug: bool = True
    allow_reset: bool = True
    database_url: str = "sqlite:///./finshield.db"
    jwt_secret: str = "finshield-lab-dev-secret-do-not-use-in-production"
    jwt_ttl_minutes: int = 60

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Settings":
        config_path = Path(path or os.environ.get("FINSHIELD_CONFIG", DEFAULT_CONFIG_PATH))
        raw: dict = {}
        if config_path.exists():
            raw = json.loads(config_path.read_text(encoding="utf-8"))
        raw.setdefault("DATABASE_URL", os.environ.get("DATABASE_URL", "sqlite:///./finshield.db"))
        raw.setdefault("JWT_SECRET", os.environ.get("JWT_SECRET", "finshield-lab-dev-secret-do-not-use-in-production"))
        return cls(
            enable_bola_bug=bool(raw.get("ENABLE_BOLA_BUG", True)),
            enable_race_condition=bool(raw.get("ENABLE_RACE_CONDITION", True)),
            enable_mcc_pollution_bug=bool(raw.get("ENABLE_MCC_POLLUTION_BUG", True)),
            enable_sim_swap_bug=bool(raw.get("ENABLE_SIM_SWAP_BUG", True)),
            allow_reset=bool(raw.get("ALLOW_RESET", True)),
            database_url=str(raw["DATABASE_URL"]),
            jwt_secret=str(raw["JWT_SECRET"]),
            jwt_ttl_minutes=int(raw.get("JWT_TTL_MINUTES", 60)),
        )
