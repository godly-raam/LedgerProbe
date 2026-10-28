from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from ..config import Settings
from ..db import Base
from ..security import get_settings
from ..seed import seed

router = APIRouter(prefix="/api/v1/dev", tags=["lab"])


@router.post("/reset")
def reset_lab(request: Request, settings: Settings = Depends(get_settings)):
    if not settings.allow_reset:
        raise HTTPException(status_code=403, detail="lab reset disabled")
    engine = request.app.state.engine
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with request.app.state.session_factory() as db:
        seed(db)
    return {"status": "reset", "detail": "seed data restored"}
