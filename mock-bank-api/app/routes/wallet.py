from __future__ import annotations

import asyncio
import json
from datetime import date

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import Allowance, Payment, User, Wallet
from ..schemas import PayRequest
from ..security import get_current_user, get_db, get_settings, require_role

router = APIRouter(prefix="/api/v1/wallet", tags=["wallet"])

KNOWN_MCCS = {"5411", "5812", "7995", "7800", "4111"}
RACE_WINDOW_SECONDS = 0.08


def _today() -> str:
    return date.today().isoformat()


@router.post("/pay")
async def pay(
    payload: PayRequest,
    teen: User = Depends(require_role("teen")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    allowance = db.get(Allowance, teen.id)
    wallet = db.get(Wallet, teen.id)
    if allowance is None or wallet is None:
        raise HTTPException(status_code=409, detail="wallet not provisioned")

    supplied = payload.mcc if isinstance(payload.mcc, list) else [payload.mcc]
    if settings.enable_mcc_pollution_bug:
        # Intentional: policy inspects the first value, the ledger books the last.
        check_mcc, booked_mcc = supplied[0].strip(), supplied[-1].strip()
    else:
        normalized = {value.strip() for value in supplied}
        if len(normalized) != 1:
            raise HTTPException(status_code=422, detail="conflicting mcc values")
        check_mcc = booked_mcc = normalized.pop()
        if booked_mcc not in KNOWN_MCCS:
            raise HTTPException(status_code=422, detail="unknown mcc")

    blocked = {code.strip() for code in json.loads(allowance.blocked_mccs or "[]")}
    if check_mcc in blocked:
        raise HTTPException(status_code=403, detail="merchant category blocked by family policy")

    amount = payload.amount_cents
    today = _today()

    if settings.enable_race_condition:
        # Intentional TOCTOU: both reads happen before the await, both writes use
        # the stale values, so concurrent requests overwrite each other.
        balance = wallet.balance_cents
        spent = allowance.spent_today_cents if allowance.spent_day == today else 0
        if spent + amount > allowance.daily_limit_cents:
            raise HTTPException(status_code=403, detail="daily spending limit exceeded")
        if balance < amount:
            raise HTTPException(status_code=402, detail="insufficient funds")

        await asyncio.sleep(RACE_WINDOW_SECONDS)

        allowance.spent_day = today
        allowance.spent_today_cents = spent + amount
        wallet.balance_cents = balance - amount
        payment = Payment(
            teen_id=teen.id,
            merchant=payload.merchant,
            mcc=booked_mcc,
            amount_cents=amount,
            status="approved",
        )
        db.add(payment)
        db.commit()
        db.refresh(payment)
    else:
        if allowance.spent_day != today:
            allowance.spent_day = today
            allowance.spent_today_cents = 0
            db.flush()

        # Atomic guards: a single UPDATE per invariant, evaluated inside SQLite's
        # write transaction, so parallel payments cannot both pass the check.
        spend_ok = db.execute(
            update(Allowance)
            .where(
                Allowance.teen_id == teen.id,
                Allowance.spent_today_cents + amount <= Allowance.daily_limit_cents,
            )
            .values(spent_today_cents=Allowance.spent_today_cents + amount)
        )
        if spend_ok.rowcount != 1:
            db.rollback()
            raise HTTPException(status_code=403, detail="daily spending limit exceeded")

        balance_ok = db.execute(
            update(Wallet)
            .where(Wallet.teen_id == teen.id, Wallet.balance_cents >= amount)
            .values(balance_cents=Wallet.balance_cents - amount)
        )
        if balance_ok.rowcount != 1:
            db.rollback()
            raise HTTPException(status_code=402, detail="insufficient funds")

        payment = Payment(
            teen_id=teen.id,
            merchant=payload.merchant,
            mcc=booked_mcc,
            amount_cents=amount,
            status="approved",
        )
        db.add(payment)
        db.commit()
        db.refresh(payment)

    db.refresh(wallet)
    return {
        "payment_id": payment.id,
        "status": payment.status,
        "amount_cents": amount,
        "mcc": booked_mcc,
        "merchant": payload.merchant,
        "balance_cents": wallet.balance_cents,
        "daily_limit_cents": allowance.daily_limit_cents,
        "spent_today_cents": allowance.spent_today_cents,
    }


@router.get("/balance")
def balance(teen: User = Depends(require_role("teen")), db: Session = Depends(get_db)):
    wallet = db.get(Wallet, teen.id)
    if wallet is None:
        raise HTTPException(status_code=404, detail="wallet not provisioned")
    return {"teen_id": wallet.teen_id, "balance_cents": wallet.balance_cents, "currency": wallet.currency}


@router.get("/transactions/{teen_id}")
def transactions(
    teen_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    teen = db.get(User, teen_id)
    if teen is None or teen.role != "teen":
        raise HTTPException(status_code=404, detail="teen not found")
    if user.role == "parent":
        if not settings.enable_bola_bug and teen.parent_id != user.id:
            raise HTTPException(status_code=403, detail="teen is not in your family")
    elif not (user.role == "teen" and user.id == teen.id):
        raise HTTPException(status_code=403, detail="not allowed")

    rows = db.scalars(
        select(Payment).where(Payment.teen_id == teen_id).order_by(Payment.id.desc()).limit(100)
    ).all()
    return {
        "teen_id": teen_id,
        "count": len(rows),
        "transactions": [
            {
                "id": row.id,
                "merchant": row.merchant,
                "mcc": row.mcc,
                "amount_cents": row.amount_cents,
                "status": row.status,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ],
    }
