from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import Allowance, User
from ..schemas import AllowanceUpdate
from ..security import get_current_user, get_db, get_settings, require_role

router = APIRouter(prefix="/api/v1/family", tags=["family"])


def _teen_or_404(db: Session, teen_id: str) -> User:
    teen = db.get(User, teen_id)
    if teen is None or teen.role != "teen":
        raise HTTPException(status_code=404, detail="teen not found")
    return teen


def _allowed(db: Session, teen: User, parent_id: str) -> None:
    if teen.parent_id != parent_id:
        raise HTTPException(status_code=403, detail="teen is not in your family")


def _allowance_payload(allowance: Allowance) -> dict:
    return {
        "teen_id": allowance.teen_id,
        "parent_id": allowance.parent_id,
        "daily_limit_cents": allowance.daily_limit_cents,
        "blocked_mccs": json.loads(allowance.blocked_mccs or "[]"),
        "spent_today_cents": allowance.spent_today_cents,
    }


@router.post("/allowance")
def set_allowance(
    payload: AllowanceUpdate,
    parent: User = Depends(require_role("parent")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    teen = _teen_or_404(db, payload.teen_id)
    # Intentional BOLA: toggle off to enforce the ownership check.
    if not settings.enable_bola_bug:
        _allowed(db, teen, parent.id)

    allowance = db.get(Allowance, teen.id)
    if allowance is None:
        allowance = Allowance(teen_id=teen.id, parent_id=parent.id, daily_limit_cents=0)
        db.add(allowance)
    allowance.parent_id = parent.id
    allowance.daily_limit_cents = payload.daily_limit_cents
    allowance.blocked_mccs = json.dumps(payload.blocked_mccs)
    db.commit()
    db.refresh(allowance)
    return _allowance_payload(allowance)


@router.get("/allowance/{teen_id}")
def get_allowance(
    teen_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    teen = _teen_or_404(db, teen_id)
    if user.role == "parent":
        if not settings.enable_bola_bug:
            _allowed(db, teen, user.id)
    elif not (user.role == "teen" and user.id == teen.id):
        raise HTTPException(status_code=403, detail="not allowed")

    allowance = db.get(Allowance, teen.id)
    if allowance is None:
        raise HTTPException(status_code=404, detail="allowance not configured")
    return _allowance_payload(allowance)
