from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import User
from ..schemas import LoginRequest
from ..security import (
    create_access_token,
    get_current_user,
    get_db,
    get_settings,
    public_user,
    verify_password,
)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/login")
def login(
    payload: LoginRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    user = db.scalar(select(User).where(User.email == payload.email.strip().lower()))
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="invalid credentials")
    return {
        "access_token": create_access_token(settings, user),
        "token_type": "bearer",
        "expires_in": settings.jwt_ttl_minutes * 60,
        "user": public_user(user),
    }


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return public_user(user)
