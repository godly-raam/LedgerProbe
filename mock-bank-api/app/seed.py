from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Allowance, Device, User, Wallet
from .security import hash_password

DEMO_PASSWORD = "demo1234"
MOCK_OTP = "246810"

SEED_USERS = [
    {"id": "usr_parent_a", "email": "parent.a@finshield.dev", "display_name": "Parent A", "role": "parent", "parent_id": None},
    {"id": "usr_parent_b", "email": "parent.b@finshield.dev", "display_name": "Parent B", "role": "parent", "parent_id": None},
    {"id": "usr_teen_a", "email": "teen.a@finshield.dev", "display_name": "Teen A", "role": "teen", "parent_id": "usr_parent_a"},
    {"id": "usr_teen_b", "email": "teen.b@finshield.dev", "display_name": "Teen B", "role": "teen", "parent_id": "usr_parent_b"},
    {"id": "usr_merchant", "email": "merchant@finshield.dev", "display_name": "MegaMart", "role": "merchant", "parent_id": None},
    {"id": "usr_admin", "email": "admin@finshield.dev", "display_name": "Lab Admin", "role": "admin", "parent_id": None},
]

ALLOWANCES = [
    {"teen_id": "usr_teen_a", "parent_id": "usr_parent_a", "daily_limit_cents": 5000, "blocked_mccs": ["7995"]},
    {"teen_id": "usr_teen_b", "parent_id": "usr_parent_b", "daily_limit_cents": 20000, "blocked_mccs": ["7995", "7800"]},
]

WALLETS = [
    {"teen_id": "usr_teen_a", "balance_cents": 12000},
    {"teen_id": "usr_teen_b", "balance_cents": 50000},
]

DEVICES = [
    {
        "teen_id": "usr_teen_a",
        "sim_serial": "89014103211118510720",
        "attestation_provider": "software",
        "strongbox": False,
        "key_attested": False,
    },
    {
        "teen_id": "usr_teen_b",
        "sim_serial": "89014103211118510721",
        "attestation_provider": "strongbox",
        "strongbox": True,
        "key_attested": True,
    },
]


def seed(db: Session) -> None:
    if db.scalar(select(User).limit(1)) is not None:
        return

    for spec in SEED_USERS:
        db.add(User(**spec, password_hash=hash_password(DEMO_PASSWORD)))
    db.flush()

    for spec in ALLOWANCES:
        db.add(
            Allowance(
                teen_id=spec["teen_id"],
                parent_id=spec["parent_id"],
                daily_limit_cents=spec["daily_limit_cents"],
                blocked_mccs=json.dumps(spec["blocked_mccs"]),
            )
        )
    for spec in WALLETS:
        db.add(Wallet(**spec))
    for spec in DEVICES:
        db.add(Device(**spec))

    db.commit()
