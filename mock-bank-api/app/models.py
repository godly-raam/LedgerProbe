from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Role(str, enum.Enum):
    parent = "parent"
    teen = "teen"
    merchant = "merchant"
    admin = "admin"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(80))
    role: Mapped[str] = mapped_column(String(16))
    parent_id: Mapped[str | None] = mapped_column(String(40), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Allowance(Base):
    __tablename__ = "allowances"

    teen_id: Mapped[str] = mapped_column(String(40), ForeignKey("users.id"), primary_key=True)
    parent_id: Mapped[str] = mapped_column(String(40), ForeignKey("users.id"))
    daily_limit_cents: Mapped[int] = mapped_column(Integer, default=0)
    blocked_mccs: Mapped[str] = mapped_column(Text, default="[]")
    spent_today_cents: Mapped[int] = mapped_column(Integer, default=0)
    spent_day: Mapped[str] = mapped_column(String(10), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Wallet(Base):
    __tablename__ = "wallets"

    teen_id: Mapped[str] = mapped_column(String(40), ForeignKey("users.id"), primary_key=True)
    balance_cents: Mapped[int] = mapped_column(Integer, default=0)
    currency: Mapped[str] = mapped_column(String(3), default="USD")


class Payment(Base):
    __tablename__ = "payments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    teen_id: Mapped[str] = mapped_column(String(40), ForeignKey("users.id"), index=True)
    merchant: Mapped[str] = mapped_column(String(80))
    mcc: Mapped[str] = mapped_column(String(8))
    amount_cents: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16))
    decline_reason: Mapped[str | None] = mapped_column(String(80), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Device(Base):
    __tablename__ = "devices"

    teen_id: Mapped[str] = mapped_column(String(40), ForeignKey("users.id"), primary_key=True)
    sim_serial: Mapped[str] = mapped_column(String(40))
    attestation_provider: Mapped[str] = mapped_column(String(20), default="software")
    strongbox: Mapped[bool] = mapped_column(Boolean, default=False)
    key_attested: Mapped[bool] = mapped_column(Boolean, default=False)
    rebinds: Mapped[int] = mapped_column(Integer, default=0)
    bound_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
