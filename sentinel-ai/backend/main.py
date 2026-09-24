"""
backend/main.py
===============
FastAPI application entrypoint.

- Registers all routers under /api/*
- Mounts WebSocket at /ws/realtime
- Manages lifespan events: DB pool open/close, scheduler start/stop,
  monitoring collector start, ML model load.
"""
from __future__ import annotations

import contextlib
import logging
from collections.abc import AsyncGenerator

import structlog
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse

from backend.config import get_settings
from backend.middleware.audit import AuditMiddleware
from backend.middleware.rate_limit import configure_rate_limiter

# ── Router imports ────────────────────────────────────────────────────────────
from backend.routers import (
    dashboard,
    logs,
    network,
    processes,
    response,
    settings as settings_router,
    threats,
    users,
)
from backend.auth.router import router as auth_router
from backend.websocket.realtime import router as ws_router

logger = structlog.get_logger(__name__)
_settings = get_settings()


# ── Lifespan: startup & shutdown ──────────────────────────────────────────────
@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Ordered startup:
      1. Database connection pool
      2. Local SQLite init
      3. APScheduler (monitoring + intel refresh + ML retrain jobs)
      4. Load latest ML model
      5. Start ETW monitor (separate thread)

    Ordered shutdown (reverse):
      5. Stop ETW
      4. (model stays in memory until process exits)
      3. Stop scheduler
      2. Close local DB
      1. Close PG pool
    """
    logger.info("sentinel_ai_starting", env=_settings.app_env)

    # -- 1. PostgreSQL pool
    from database.connection import init_db, close_db
    await init_db()

    # -- 2. Local SQLite
    from database.local_db import init_local_db
    await init_local_db()

    # -- 3. Scheduler
    from monitoring.collector import start_collector, stop_collector
    from threat_intel.manager import start_intel_manager, stop_intel_manager
    from ai_engine.trainer import start_trainer, stop_trainer
    await start_collector()
    await start_intel_manager()
    await start_trainer()

    # -- 4. Load ML model
    from ai_engine.model_store import load_latest_model
    load_latest_model()

    logger.info("sentinel_ai_ready", host=_settings.app_host, port=_settings.app_port)

    yield  # ← application runs here

    # -- Shutdown
    logger.info("sentinel_ai_shutting_down")
    await stop_collector()
    await stop_intel_manager()
    await stop_trainer()
    await close_db()
    logger.info("sentinel_ai_stopped")


# ── Application factory ───────────────────────────────────────────────────────
def create_app() -> FastAPI:
    app = FastAPI(
        title="SentinelAI",
        description="Local-first AI-powered autonomous security monitoring — REST + WebSocket API.",
        version="1.0.0",
        default_response_class=ORJSONResponse,
        docs_url="/docs" if not _settings.is_production else None,
        redoc_url="/redoc" if not _settings.is_production else None,
        openapi_url="/openapi.json" if not _settings.is_production else None,
        lifespan=lifespan,
    )

    # ── CORS (localhost only in production) ──────────────────────────────────
    origins = ["http://localhost:3000", "http://localhost:5173"] if not _settings.is_production else []
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Audit middleware ──────────────────────────────────────────────────────
    app.add_middleware(AuditMiddleware)

    # ── Rate limiting ─────────────────────────────────────────────────────────
    configure_rate_limiter(app)

    # ── Routers ───────────────────────────────────────────────────────────────
    API_PREFIX = "/api"
    app.include_router(auth_router,          prefix=f"{API_PREFIX}/auth",     tags=["Auth"])
    app.include_router(dashboard.router,     prefix=f"{API_PREFIX}/dashboard", tags=["Dashboard"])
    app.include_router(processes.router,     prefix=f"{API_PREFIX}/processes", tags=["Processes"])
    app.include_router(network.router,       prefix=f"{API_PREFIX}/network",   tags=["Network"])
    app.include_router(threats.router,       prefix=f"{API_PREFIX}/threats",   tags=["Threats"])
    app.include_router(response.router,      prefix=f"{API_PREFIX}/response",  tags=["Response"])
    app.include_router(logs.router,          prefix=f"{API_PREFIX}/logs",      tags=["Logs"])
    app.include_router(settings_router.router, prefix=f"{API_PREFIX}/settings", tags=["Settings"])
    app.include_router(users.router,         prefix=f"{API_PREFIX}/users",     tags=["Users"])

    # ── WebSocket ─────────────────────────────────────────────────────────────
    app.include_router(ws_router,            tags=["WebSocket"])

    # ── Health check (unauthenticated) ────────────────────────────────────────
    @app.get("/health", tags=["Health"], include_in_schema=False)
    async def health() -> dict:
        return {"status": "ok", "service": "SentinelAI"}

    return app


app = create_app()


if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host=_settings.app_host,
        port=_settings.app_port,
        log_level=_settings.app_log_level.lower(),
        reload=not _settings.is_production,
    )
