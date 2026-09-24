"""
ai_engine/isolation_forest.py
==============================
Isolation Forest inference engine.

- classify_batch(): classifies a full monitoring cycle's worth of snapshots
- classify_one(): classifies a single process snapshot
- Outputs: threat_level (Normal/Suspicious/Critical), anomaly_score, top_features

Target: < 500ms for a batch of 200 processes (well within sklearn's capability).
Model is loaded from model_store and accessed thread-safely.
"""
from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import numpy as np
import structlog

from ai_engine.feature_extractor import (
    FEATURE_NAMES,
    N_FEATURES,
    extract_features,
    features_to_dict,
)
from ai_engine.model_store import get_model, get_model_version
from backend.config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="iforest")


async def classify_batch(
    proc_snaps: list[dict[str, Any]],
    net_connections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Classify all process snapshots in a single batch inference call.
    Returns list of threat event dicts (only Suspicious and Critical).
    """
    if not proc_snaps:
        return []

    loop = asyncio.get_event_loop()
    start = time.monotonic()

    # Build feature vectors concurrently (I/O bound: enrichment + baseline)
    from monitoring.resource_baseline import baseline
    from threat_intel.enricher import enrich_process

    enrichment_tasks = [enrich_process(snap) for snap in proc_snaps]
    enrichments = await asyncio.gather(*enrichment_tasks, return_exceptions=True)

    feature_vectors: list[np.ndarray] = []
    valid_snaps: list[dict] = []
    valid_enrichments: list[dict] = []

    for snap, enrichment in zip(proc_snaps, enrichments):
        if isinstance(enrichment, Exception):
            enrichment = {}
        deviations = baseline.get_deviations(
            process_name=snap.get("name", ""),
            cpu=snap.get("cpu_percent", 0.0),
            ram_mb=snap.get("ram_mb", 0.0),
            net_sent=snap.get("net_sent_mb", 0.0),
            net_recv=snap.get("net_recv_mb", 0.0),
            conn_count=snap.get("conn_count", 0),
        )
        vec = extract_features(snap, net_connections, enrichment, deviations)
        feature_vectors.append(vec)
        valid_snaps.append(snap)
        valid_enrichments.append(enrichment)

    if not feature_vectors:
        return []

    # Run Isolation Forest in thread pool (CPU bound)
    X = np.stack(feature_vectors)
    scores, labels = await loop.run_in_executor(_executor, _predict, X)

    elapsed_ms = round((time.monotonic() - start) * 1000, 1)
    logger.debug("batch_classified", count=len(proc_snaps), elapsed_ms=elapsed_ms)

    # Build threat event dicts
    events: list[dict[str, Any]] = []
    for snap, vec, enrichment, score, label in zip(
        valid_snaps, feature_vectors, valid_enrichments, scores, labels
    ):
        threat_level = _score_to_level(score)

        # Override to Critical if YARA or hash match
        if enrichment.get("hash_is_malicious") or enrichment.get("yara_hit"):
            threat_level = "Critical"

        if threat_level == "Normal" and not (
            enrichment.get("hash_is_malicious") or enrichment.get("yara_hit")
        ):
            continue  # Skip persisting normal events

        top_features = _get_top_features(vec, n=3)
        trigger = _determine_trigger(enrichment, threat_level)

        events.append({
            "threat_level": threat_level,
            "anomaly_score": round(float(score), 4),
            "trigger_type": trigger,
            "feature_vector": features_to_dict(vec),
            "top_features": top_features,
            "ml_model_version": get_model_version(),
            "is_resolved": False,
        })

    return events


def _predict(X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Run Isolation Forest predict + decision_function. Synchronous — for thread pool."""
    model = get_model()
    if model is None:
        # No model yet — return neutral scores
        return np.zeros(len(X), dtype=np.float32), np.ones(len(X), dtype=np.int32)
    scores = model.decision_function(X)  # Higher = more normal
    labels = model.predict(X)            # -1 = anomaly, 1 = normal
    return scores, labels


def _score_to_level(score: float) -> str:
    suspicious_thresh = settings.ml_anomaly_suspicious_threshold   # default -0.1
    critical_thresh = settings.ml_anomaly_critical_threshold        # default -0.3
    if score <= critical_thresh:
        return "Critical"
    elif score <= suspicious_thresh:
        return "Suspicious"
    return "Normal"


def _get_top_features(vec: np.ndarray, n: int = 3) -> list[dict]:
    """
    Return the N features with highest absolute value (most anomalous).
    This is a fast approximation of SHAP for tree-based models.
    """
    abs_vals = np.abs(vec)
    top_indices = np.argsort(abs_vals)[::-1][:n]
    result = []
    for idx in top_indices:
        val = float(vec[idx])
        result.append({
            "feature": FEATURE_NAMES[idx],
            "value": round(val, 4),
            "baseline_mean": 0.0,   # Populated by explainer.py for detailed view
            "deviation": round(abs(val), 4),
            "direction": "above" if val > 0 else "below",
        })
    return result


def _determine_trigger(enrichment: dict, threat_level: str) -> str:
    if enrichment.get("yara_hit"):
        return "yara_match"
    if enrichment.get("hash_is_malicious"):
        return "hash_match"
    return "process"
