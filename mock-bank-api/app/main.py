from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from .config import Settings
from .db import Base, make_engine, make_session_factory
from .routes import auth, dev, device, family, wallet
from .seed import seed


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or Settings.load()
    engine = make_engine(resolved.database_url)
    session_factory = make_session_factory(engine)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        Base.metadata.create_all(engine)
        with session_factory() as db:
            seed(db)
        yield
        engine.dispose()

    app = FastAPI(
        title="FinShield Mock Neobank API",
        description="Intentionally vulnerable parent-teen neobank used as a security test target.",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.settings = resolved
    app.state.engine = engine
    app.state.session_factory = session_factory

    for module in (auth, family, wallet, device, dev):
        app.include_router(module.router)

    @app.get("/health", tags=["lab"])
    def health():
        return {
            "status": "ok",
            "service": "mock-bank-api",
            "vulnerabilities": {
                "bola": resolved.enable_bola_bug,
                "race_condition": resolved.enable_race_condition,
                "mcc_pollution": resolved.enable_mcc_pollution_bug,
                "sim_swap": resolved.enable_sim_swap_bug,
            },
        }

    return app
