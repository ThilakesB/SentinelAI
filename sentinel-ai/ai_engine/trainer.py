"""
ai_engine/trainer.py
=====================
Retraining scheduler for the Isolation Forest model.

Schedule: Daily at configured hour (default 03:00 UTC).
Training data: Rolling 7-day window of Normal-labeled process snapshots from DB.
Hot-swap: New model loaded without restarting the API server.

Minimum training samples: 500 (configurable).
Model versioning: iforest_v{YYYYMMDD_HHMMSS}.joblib
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import numpy as np
import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from sklearn.ensemble import IsolationForest

from ai_engine.feature_extractor import N_FEATURES
from ai_engine.model_store import register_model_in_db, save_model
from backend.config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()

_scheduler: AsyncIOScheduler | None = None
MIN_TRAINING_SAMPLES = 500


async def start_trainer() -> None:
    global _scheduler
    _scheduler = AsyncIOScheduler(timezone="UTC")
    _scheduler.add_job(
        _retrain_job,
        trigger=CronTrigger(hour=settings.ml_retrain_hour, minute=0),
        id="ml_retrain",
        max_instances=1,
    )
    _scheduler.start()
    logger.info("trainer_started", retrain_hour=settings.ml_retrain_hour)


async def stop_trainer() -> None:
    if _scheduler:
        _scheduler.shutdown(wait=False)


async def _retrain_job() -> None:
    """Fetch Normal training data, retrain, hot-swap model."""
    logger.info("retrain_starting")
    try:
        X = await _load_training_data(days=7)
        if X is None or len(X) < MIN_TRAINING_SAMPLES:
            logger.warning("retrain_skipped", reason="insufficient_data",
                           samples=len(X) if X is not None else 0,
                           minimum=MIN_TRAINING_SAMPLES)
            return

        version = f"v{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        from concurrent.futures import ThreadPoolExecutor
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=1) as executor:
            model = await loop.run_in_executor(executor, _train, X)

        path = save_model(model, version, sample_count=len(X))
        from ai_engine.model_store import _compute_checksum
        sha256 = _compute_checksum(path)
        await register_model_in_db(version, path, sha256, len(X))
        logger.info("retrain_complete", version=version, samples=len(X))

    except Exception as exc:
        logger.error("retrain_failed", error=str(exc), exc_info=True)


async def _load_training_data(days: int = 7) -> np.ndarray | None:
    """
    Pull process snapshots labeled Normal from the past N days.
    Reconstructs feature vectors from stored feature_vector JSONB field.
    """
    from database.connection import get_db_session
    from sqlalchemy import text

    since = datetime.now(timezone.utc) - timedelta(days=days)

    try:
        async with get_db_session() as db:
            result = await db.execute(
                text("""
                    SELECT te.feature_vector
                    FROM threat_events te
                    WHERE te.threat_level = 'Normal'
                      AND te.detected_at >= :since
                    ORDER BY te.detected_at DESC
                    LIMIT 10000
                """),
                {"since": since},
            )
            rows = result.fetchall()
    except Exception as exc:
        logger.error("training_data_load_failed", error=str(exc))
        return None

    if not rows:
        return None

    vectors = []
    for row in rows:
        fv = row[0]
        if fv and isinstance(fv, dict) and len(fv) == N_FEATURES:
            vectors.append(list(fv.values()))

    if not vectors:
        return None

    return np.array(vectors, dtype=np.float32)


def _train(X: np.ndarray) -> IsolationForest:
    """Train Isolation Forest on the provided feature matrix. Synchronous."""
    model = IsolationForest(
        n_estimators=200,
        max_samples="auto",
        contamination=0.05,   # Assume ~5% of normal traffic looks anomalous
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X)
    return model
