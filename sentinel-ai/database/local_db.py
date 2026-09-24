"""
database/local_db.py
====================
Local SQLite database for:
  - Threat intel cache (feed data with TTL)
  - Resource baseline data (survives restarts)
  - ML model version metadata

Uses aiosqlite for async access. Separate from the Supabase PG connection
so the agent works fully offline for detection (only sync layer uses PG).
"""
from __future__ import annotations

import contextlib
from pathlib import Path
from typing import AsyncGenerator

import aiosqlite
import structlog

from backend.config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()

_LOCAL_DB_PATH: Path = settings.local_db_path

# DDL for all local tables
_INIT_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS threat_intel_cache (
    cache_key   TEXT PRIMARY KEY,
    intel_type  TEXT NOT NULL,
    data_json   TEXT NOT NULL,
    source      TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cache_expires ON threat_intel_cache(expires_at);

CREATE TABLE IF NOT EXISTS resource_baseline (
    process_name        TEXT PRIMARY KEY,
    mean_cpu            REAL DEFAULT 0,
    std_cpu             REAL DEFAULT 0,
    mean_ram_mb         REAL DEFAULT 0,
    std_ram_mb          REAL DEFAULT 0,
    mean_net_sent_mb_s  REAL DEFAULT 0,
    std_net_sent_mb_s   REAL DEFAULT 0,
    mean_net_recv_mb_s  REAL DEFAULT 0,
    std_net_recv_mb_s   REAL DEFAULT 0,
    mean_conn_count     REAL DEFAULT 0,
    std_conn_count      REAL DEFAULT 0,
    sample_count        INTEGER DEFAULT 0,
    last_updated        TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS ml_model_versions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    version         TEXT UNIQUE NOT NULL,
    file_path       TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    trained_at      TEXT NOT NULL DEFAULT (datetime('now')),
    sample_count    INTEGER DEFAULT 0,
    is_active       INTEGER DEFAULT 0
);
"""


async def init_local_db() -> None:
    """Create the local SQLite schema on first run."""
    _LOCAL_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(_LOCAL_DB_PATH) as db:
        await db.executescript(_INIT_SQL)
        await db.commit()
    logger.info("local_db_initialized", path=str(_LOCAL_DB_PATH))


@contextlib.asynccontextmanager
async def get_local_db() -> AsyncGenerator[aiosqlite.Connection, None]:
    """Yield an aiosqlite connection with row_factory set to dict."""
    async with aiosqlite.connect(_LOCAL_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        yield db
