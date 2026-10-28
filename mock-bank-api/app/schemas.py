from __future__ import annotations

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    email: str
    password: str


class AllowanceUpdate(BaseModel):
    teen_id: str
    daily_limit_cents: int = Field(ge=0, le=1_000_000)
    blocked_mccs: list[str] = Field(default_factory=list)


class PayRequest(BaseModel):
    amount_cents: int = Field(gt=0, le=500_000)
    # A list is accepted on purpose: this models sloppy upstream coercion and
    # is the vector for the MCC pollution bug.
    mcc: str | list[str]
    merchant: str = Field(min_length=1, max_length=80)


class AttestationIn(BaseModel):
    provider: str = "software"  # software | tee | strongbox
    strongbox: bool = False
    key_attested: bool = False


class BindRequest(BaseModel):
    sim_serial: str = Field(min_length=8, max_length=40)
    otp: str | None = None
    attestation: AttestationIn = Field(default_factory=AttestationIn)
