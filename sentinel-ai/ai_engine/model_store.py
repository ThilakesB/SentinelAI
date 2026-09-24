"""
ai_engine/model_store.py
=========================
Versioned model artifact storage with SHA-256 integrity checks.

Model artifacts saved as:
  models/iforest_v{n}.joblib      — serialized sklearn model
  models/iforest_v{n}.sha256      — expected checksum

Version metadata tracked in local SQLite (ml_model_versions table).
Active model is thread-safe via asyncio.Lock.
"""
from __future__ import annotations

import asyncio
import hashlib
import threading
from pathlib import Path
from typing import Optional

import joblib
import structlog
from sklearn.ensemble import IsolationForest

from backend.config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()

# Thread-safe active model container
_model_lock = threading.Lock()
_active_model: IsolationForest | None = None
_active_version: str | None = None


def get_model() -> IsolationForest | None:
    """Return the currently loaded model. Thread-safe."""
    with _model_lock:
        return _active_model


def get_model_version() -> str | None:
    with _model_lock:
        return _active_version


def load_latest_model() -> bool:
    """
    Load the most recent active model from disk.
    Called at app startup. Returns True if model loaded successfully.
    """
    models_dir = settings.ml_models_dir
    joblib_files = sorted(models_dir.glob("iforest_v*.joblib"), reverse=True)

    for path in joblib_files:
        version = path.stem.replace("iforest_", "")
        if _verify_checksum(path):
            model = joblib.load(path)
            with _model_lock:
                global _active_model, _active_version
                _active_model = model
                _active_version = version
            logger.info("model_loaded", version=version, path=str(path))
            return True
        else:
            logger.warning("model_checksum_failed", path=str(path))

    logger.warning("no_valid_model_found", note="Run scripts/train_baseline.py first")
    return False


def save_model(model: IsolationForest, version: str, sample_count: int) -> Path:
    """
    Save a new model version with checksum. Hot-swaps the active model.
    Returns the path to the saved model file.
    """
    models_dir = settings.ml_models_dir
    models_dir.mkdir(parents=True, exist_ok=True)

    model_path = models_dir / f"iforest_{version}.joblib"
    joblib.dump(model, model_path, compress=3)

    # Write checksum
    checksum = _compute_checksum(model_path)
    checksum_path = models_dir / f"iforest_{version}.sha256"
    checksum_path.write_text(checksum)

    # Hot-swap
    with _model_lock:
        global _active_model, _active_version
        _active_model = model
        _active_version = version

    logger.info("model_saved", version=version, path=str(model_path),
                sha256=checksum[:16], samples=sample_count)
    return model_path


def _compute_checksum(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _verify_checksum(model_path: Path) -> bool:
    checksum_path = model_path.with_suffix(".sha256")
    if not checksum_path.exists():
        return False
    expected = checksum_path.read_text().strip()
    actual = _compute_checksum(model_path)
    return expected == actual


async def register_model_in_db(version: str, path: Path, sha256: str, sample_count: int) -> None:
    """Record new model version in local SQLite ml_model_versions table."""
    from database.local_db import get_local_db
    async with get_local_db() as db:
        # Deactivate all previous versions
        await db.execute("UPDATE ml_model_versions SET is_active = 0")
        await db.execute(
            "INSERT OR REPLACE INTO ml_model_versions "
            "(version, file_path, sha256, sample_count, is_active) "
            "VALUES (?, ?, ?, ?, 1)",
            (version, str(path), sha256, sample_count),
        )
        await db.commit()
    logger.info("model_registered_in_db", version=version)
