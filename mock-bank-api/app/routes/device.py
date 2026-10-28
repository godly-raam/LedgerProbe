from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import Device, User
from ..schemas import BindRequest
from ..security import get_current_user, get_db, get_settings, require_role
from ..seed import MOCK_OTP

router = APIRouter(prefix="/api/v1/device", tags=["device"])


def _device_payload(device: Device) -> dict:
    return {
        "teen_id": device.teen_id,
        "sim_serial": device.sim_serial,
        "attestation": {
            "provider": device.attestation_provider,
            "strongbox": device.strongbox,
            "key_attested": device.key_attested,
            "bound_at": device.bound_at.isoformat(),
        },
        "rebinds": device.rebinds,
    }


@router.post("/bind")
def bind(
    payload: BindRequest,
    teen: User = Depends(require_role("teen")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    device = db.get(Device, teen.id)
    is_rebind = device is not None and device.sim_serial != payload.sim_serial

    # Intentional SIM-swap flaw: a rebind only needs the (static) OTP when the
    # toggle is off. With it on, possessing the account token is enough.
    if is_rebind and not settings.enable_sim_swap_bug and payload.otp != MOCK_OTP:
        raise HTTPException(status_code=403, detail="otp required to rebind sim")

    if device is None:
        device = Device(teen_id=teen.id)
        db.add(device)

    device.sim_serial = payload.sim_serial
    device.attestation_provider = payload.attestation.provider
    device.strongbox = payload.attestation.strongbox
    device.key_attested = payload.attestation.key_attested
    device.rebinds = device.rebinds + 1 if is_rebind else device.rebinds
    device.bound_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(device)
    return {"status": "bound", "rebind": is_rebind, **_device_payload(device)}


@router.get("/{teen_id}")
def get_device(
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

    device = db.get(Device, teen_id)
    if device is None:
        raise HTTPException(status_code=404, detail="device not bound")
    return _device_payload(device)
